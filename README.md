# Widevine Proxy

A Golang implementation of Google Widevine Proxy

## Accreditation 

This repostory is based on [alfg/widevine](https://github.com/alfg/widevine). Thanks for his effort to create the foundation of this code.

Major Modify:

1. Added logrus for some basic logging.

2. Added error handling on http request, body parsing, and cryptos.

3. Restructed the code.
## Usage

### Define KeyGoverner

```golang
type KeyGoverner interface {
	GenerateContentKeyID(contentID []byte) []byte
	GenerateContentKey(contentID []byte) []byte
	GenerateContentIV(contentID []byte) []byte
	GenerateContentKeySpec(contentID []byte, policyConfig map[string]string) (*[]ContentKeySpec, error)
}
```
### New

```golang

key := []byte("Widevine Key")
iv := []byte("Widevine iv")
provider := "widevine_test"
keyGenerator := FakeKeyGoverner{}

logger := logrus.New()
/*
    Setup Logger ... 
*/

wp := NewWidevineProxy(key, iv, provider, keyGenerator, logger)
```

### Get License
```golang
    /*
        Request License
    */
    licenseResponse, err := wp.GetLicense(contetntID, requestBody)
}
```