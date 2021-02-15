package widevineproxy

import (
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// Ref: https://www.widevine.com/news
	// Updated At:  2021/01/14

	/*
		Widevine Modular
	*/

	widevineModularUATGetLicenseURL = "https://license.uat.widevine.com/cenc/getlicense/"
	widevineModularUATGetKeyURL     = "https://license.uat.widevine.com/cenc/getcontentkey/"

	widevineModularStagingGetLicenseURL = "https://license.staging.widevine.com/cenc/getlicense/"
	widevineModularStagingGetKeyURL     = "https://license.staging.widevine.com/cenc/getcontentkey/"

	widevineModularProductionGetLicenseURL = "https://license.widevine.com/cenc/getlicense/"
	widevineModularProductionGetKeyURL     = "https://license.widevine.com/cenc/getcontentkey/"

	/*
		Widevine Classic
	*/

	widevineClassicUATGetLicenseURL = "https://license.uat.widevine.com/cas/getlicense/"
	widevineClassicUATGetKeyURL     = "https://license.uat.widevine.com/cas/getcontentkey/"

	widevineClassicStagingGetLicenseURL = "https://license.staging.widevine.com/cas/getlicense/"
	widevineClassicStagingGetKeyURL     = "https://license.staging.widevine.com/cas/getcontentkey/"

	widevineClassicProductionGetLicenseURL = "https://license.widevine.com/cas/getlicense/"
	widevineClassicProductionGetKeyURL     = "https://license.widevine.com/cas/getcontentkey/"
)

// KeyGoverner is a business logic for judging the premissions in multi-key protection
type KeyGoverner interface {
	GenerateContentKeyID(contentID []byte) []byte
	GenerateContentKey(contentID []byte) []byte
	GenerateContentIV(contentID []byte) []byte
	GenerateContentKeySpec(contentID []byte, policyConfig map[string]string) (*[]ContentKeySpec, error)
}

// Proxy structure.
type Proxy struct {
	PartnerRootKey      []byte
	PartnerRootIV       []byte
	Provider            string
	ContentKeyGenerator KeyGoverner
	httpCaller          *http.Client
	Logger              *logrus.Logger
}

// NewWidevineProxy creates an instance for grant widevine license with Widevine Cloud-based services.
func NewWidevineProxy(key, iv []byte, provider string, keyGenerator KeyGoverner, logger *logrus.Logger) *Proxy {
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	return &Proxy{
		PartnerRootKey:      key,
		PartnerRootIV:       iv,
		Provider:            provider,
		ContentKeyGenerator: keyGenerator,
		Logger:              logger,
		httpCaller:          client,
	}
}
