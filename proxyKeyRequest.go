package widevineproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/alfg/widevine/proto"
	protobuf "github.com/golang/protobuf/proto"
)

// GetContentKeyResponse JSON response from Widevine Cloud.
// /cenc/getcontentkey/<provider>
type ContentKeyResponse struct {
	Status      string   `json:"status"`
	DRM         []drm    `json:"drm"`
	Tracks      []tracks `json:"tracks"`
	AlreadyUsed bool     `json:"already_used"`
}

type drm struct {
	Type     string `json:"type"`
	SystemID string `json:"system_id"`
}

type tracks struct {
	Type  string `json:"type"`
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
	PSSH  []pssh `json:"pssh"`
}

type pssh struct {
	DRMType string `json:"drm_type"`
	Data    string `json:"data"`
}

// Policy struct to set policy options for a ContentKey request.
type Policy struct {
	ContentID string
	Tracks    []string
	DRMTypes  []string
	Policy    string
}

// GetContentKey creates a content key giving a contentID.
func (wp *Proxy) GetContentKey(contentID string, policy Policy) (*ContentKeyResponse, error) {
	p := wp.setPolicy(contentID, policy)
	payload, err := json.Marshal(wp.buildCKMessage(p))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", getCloudLicenseServiceURL(wp.Provider, "key"), bytes.NewBuffer(payload))
	req.Header.Add("Content-Type", "application/json")
	response, err := wp.httpCaller.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	respJSON := make(map[string]string)
	err = json.NewDecoder(response.Body).Decode(&respJSON)
	if err != nil {
		return nil, err
	}
	resp, isExisted := respJSON["response"]
	if !isExisted {
		return nil, fmt.Errorf("[GET] Content Key Response is Empty")
	}

	output := &ContentKeyResponse{}
	dec, _ := base64.StdEncoding.DecodeString(resp)
	if err := json.Unmarshal(dec, &output); err != nil {
		return nil, err
	}
	// TODO
	// Build custom PSSH from protobuf.
	wp.Logger.Debugf("pssh build: %s", wp.buildPSSH(contentID))
	return output, nil
}

func (wp *Proxy) buildCKMessage(policy map[string]interface{}) map[string]interface{} {
	// Marshal and encode payload.
	jsonPayload, _ := json.Marshal(policy)
	b64payload := base64.StdEncoding.EncodeToString([]byte(jsonPayload))

	sign, err := wp.generateSignature(jsonPayload)
	if err != nil {
		return nil
	}
	// Create signature and postBody.
	postBody := map[string]interface{}{
		"request":   b64payload,
		"signature": sign,
		"signer":    wp.Provider,
	}
	return postBody
}

func (wp *Proxy) buildPSSH(contentID string) string {
	wvpssh := &proto.WidevineCencHeader{
		Provider:  protobuf.String(wp.Provider),
		ContentId: []byte(contentID),
	}
	p, _ := protobuf.Marshal(wvpssh)
	return base64.StdEncoding.EncodeToString(p)
}

func (wp *Proxy) setPolicy(contentID string, policy Policy) map[string]interface{} {
	enc := base64.StdEncoding.EncodeToString([]byte(contentID))

	// Build tracks []interface.
	var tracks []interface{}
	for _, track := range policy.Tracks {
		tracks = append(tracks, map[string]string{"type": track})
	}

	// Build policy interface.
	// TODO: Set defaults.
	p := map[string]interface{}{
		"content_id": enc,
		"tracks":     tracks,
		"drm_types":  policy.DRMTypes,
		"policy":     policy.Policy,
	}
	return p
}
