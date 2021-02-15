package widevineproxy

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

// LicenseResponse decoded JSON response from Widevine Cloud.
// /cenc/getlicense
type LicenseResponse struct {
	Status                     string             `json:"status"`
	StatusMessage              string             `json:"status_message"`
	License                    string             `json:"license"`
	LicenseMetadata            LicenseMetadata    `json:"license_metadata"`
	SupportedTracks            []interface{}      `json:"supported_tracks"`
	Make                       string             `json:"make"`
	Model                      string             `json:"model"`
	SecurityLevel              int64              `json:"security_level"`
	InternalStatus             int64              `json:"internal_status"`
	SessionState               SessionState       `json:"session_state"`
	DRMCERTSerialNumber        string             `json:"drm_cert_serial_number"`
	DeviceWhitelistState       string             `json:"device_whitelist_state"`
	MessageType                string             `json:"message_type"`
	Platform                   string             `json:"platform"`
	DeviceState                string             `json:"device_state"`
	PsshData                   PsshData           `json:"pssh_data"`
	ClientMaxHdcpVersion       string             `json:"client_max_hdcp_version"`
	ClientInfo                 []ClientInfo       `json:"client_info"`
	SignatureExpirationSecs    int64              `json:"signature_expiration_secs"`
	PlatformVerificationStatus string             `json:"platform_verification_status"`
	ContentOwner               string             `json:"content_owner"`
	ContentProvider            string             `json:"content_provider"`
	SystemID                   int64              `json:"system_id"`
	OEMCryptoAPIVersion        int64              `json:"oem_crypto_api_version"`
	ResourceRatingTier         int64              `json:"resource_rating_tier"`
	ServiceVersionInfo         ServiceVersionInfo `json:"service_version_info"`
}

type ClientInfo struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type LicenseMetadata struct {
	ContentID   string `json:"content_id"`
	LicenseType string `json:"license_type"`
	RequestType string `json:"request_type"`
}

type PsshData struct {
	KeyID     []interface{} `json:"key_id"`
	ContentID string        `json:"content_id"`
}

type ServiceVersionInfo struct {
	LicenseSDKVersion     string `json:"license_sdk_version"`
	LicenseServiceVersion string `json:"license_service_version"`
}

type SessionState struct {
	LicenseID      LicenseID `json:"license_id"`
	SigningKey     string    `json:"signing_key"`
	KeyboxSystemID int64     `json:"keybox_system_id"`
	LicenseCounter int64     `json:"license_counter"`
}

type LicenseID struct {
	RequestID  string `json:"request_id"`
	SessionID  string `json:"session_id"`
	PurchaseID string `json:"purchase_id"`
	Type       string `json:"type"`
	Version    int64  `json:"version"`
}

type LicenseMessage struct {
	Payload           string           `json:"payload"`
	ContentID         string           `json:"content_id"`
	Provider          string           `json:"provider"`
	AllowedTrackTypes string           `json:"allowed_track_types"`
	ContentKeySpecs   []ContentKeySpec `json:"content_key_specs"`
}

type ContentKeySpec struct {
	KeyID     string `json:"key_id"`
	Key       string `json:"key"`
	IV        string `json:"iv"`
	TrackType string `json:"track_type"`
}

// GetLicense creates a license request used with a proxy server.
func (wp *Proxy) GetLicense(contentID string, body string) (*LicenseResponse, error) {
	msg, err := wp.buildLicenseMessage(contentID, body)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", getCloudLicenseServiceURL(wp.Provider, "license"), bytes.NewBuffer(payload))
	req.Header.Add("Content-Type", "application/json")
	response, err := wp.httpCaller.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	b, _ := ioutil.ReadAll(response.Body)
	wp.Logger.Debug(string(b))

	var lr LicenseResponse
	if err := json.Unmarshal(b, &lr); err != nil {
		wp.Logger.Error("Get License JSON Decode Error")
		return nil, err
	}
	return &lr, nil

}

func (wp *Proxy) buildLicenseMessage(contentID string, body string) (map[string]interface{}, error) {
	wp.Logger.Debugf("Content ID: %s", contentID)
	enc := base64.StdEncoding.EncodeToString([]byte(contentID))
	contentKey := wp.ContentKeyGenerator.GenerateContentKey([]byte(contentID))

	m := md5.New()
	m.Write(contentKey)
	contentKeyID := m.Sum(nil)

	message := &LicenseMessage{
		Payload:           body,
		ContentID:         enc,
		Provider:          wp.Provider,
		AllowedTrackTypes: "SD_UHD1",
		ContentKeySpecs: []ContentKeySpec{
			{
				Key:   base64.StdEncoding.EncodeToString(contentKey),
				KeyID: base64.StdEncoding.EncodeToString(contentKeyID),
			},
		},
	}

	jsonMessage, _ := json.Marshal(message)
	b64message := base64.StdEncoding.EncodeToString(jsonMessage)
	wp.Logger.Debugf("License Message: %s", b64message)

	// Create signature and postBody.
	sign, err := wp.generateSignature(jsonMessage)
	if err != nil {
		wp.Logger.WithField("error", err.Error()).Error("Signature Error")
		return nil, err
	}
	postBody := map[string]interface{}{
		"request":   b64message,
		"signature": sign,
		"signer":    wp.Provider,
	}
	return postBody, nil
}

func getCloudLicenseServiceURL(provider, purpose string) string {
	if strings.ToLower(purpose) == "key" {
		switch provider {
		case "widevine_test":
			return (widevineModularUATGetKeyURL + "widevine_test")
		default:
			return (widevineModularProductionGetKeyURL + "widevine_test")
		}
	}

	if strings.ToLower(purpose) == "license" {
		switch provider {
		case "widevine_test":
			return (widevineModularUATGetLicenseURL + "widevine_test")
		default:
			return (widevineModularProductionGetLicenseURL + "widevine_test")
		}
	}
	return ""
}

func (wp *Proxy) generateSignature(payload []byte) ([]byte, error) {
	h := sha1.New()
	h.Write([]byte(payload))

	ciphertext, err := AESCBCEncrypt(wp.PartnerRootKey, wp.PartnerRootIV, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
