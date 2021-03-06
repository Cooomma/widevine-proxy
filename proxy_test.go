package widevineproxy

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Test Challenge simulating a request from a Widevine CDM payload.
// https://demo.unified-streaming.com/video/tears-of-steel/tears-of-steel-dash-widevine.ism/.mpd
const testLicenseChallenge = `CAESrSsSMAouChgiEGZrajNsamFTZGZhbGtyM2pI49yVmwYQARoQu3Vayko4ZhfP2lfCWQD+DhgBIIzHxu8FMBVC7ioKEnN0YWdpbmcuZ29vZ2xlLmNvbRIQKHA0VMAI9jYYredEPbbEyBqwKGGmP9x097DeCTnqiY8TNYYpUIi+raHm1geSBhlMJpTgPHCoARPwEnUmj0QrRE0Oc2mVW3E1fBwFEiJVzboydy/c2UBknjnSc8KuvSBiquNz7JtNgaysOQ02h497goY//p+BeQOHO8GiiEw6WYBIi7//9kZKHJX1SoWx28sg6IgrHuqy12n/aWkFjmydBFjuq5kinDQbnKSgCgYgpP5k2P6gCP17Qy7RQWOgf2RqcJS9cQJDkl+chkmlkBSNefWEHAymeg23tzogjD8E6bcgIQcwzltWTSKzoX7LRQK9wBTHsJD5G2C7UBfA7gbNfCphJphrB4vU845VKDYqYaV0JLT8K80GmRU/GqXXHIAb6PB9ZpFjQeBF1Tf22mTEm11p0bigEdnUc1NBHJDFzH4pXWyqw6bcm7b0FrFiU0c++XNGvU6r9zNwp6Og83seHg0qHeel6rvd9W/4Z9hW1GO4sKFVR8px5Iv+wnuTezAGAEMfSIKCX9pDa2OW4sihn7p1+o22JcSZJPJ3i4BHx7blz727YQn26hbmpUxpTGk1c80KD6PoxhMC9RRloHurypsDwr+dXpcsFWwh0j/fCCI24bq6pDyDFuRVyHOAAP3LujAd0Epbsl4YxS78Wfd0CsOuSjvSUqFsKkvWIlrvOvQew3mza2St9zqkRSY+pOH8IfZIgz7gpUAOe1czKWIVRzmu3lhEUJMG1xU8GlAkZGVFNuyGGjoV25LoeL48jo7Kun7PtCP3xR1amvZk3oBBxlZWQjF8pmrLq+WE2WGH1big1ZvksvKQmWBiOLxE4J3p/+XgVCXpPzcbgaK8/uEzTt+XKrSp5Jdte9gfZxHA3HKugyOrUfYHYq8EDrgOdgnYKCE7ZWr0SMH2HLDO9GUwajK1W4ks5tfi6uoVhl+F0H9/NG9+uRl8ChCJh5bcyi0dCxa/+Sb2N+hntJsrFRA+kuon22naSDcgCoH7Dqsay07TLFdnIiVGg3dsrZD/Ce8CDwGp/IV0dOOASGMPduT8Z/D+wKZ/lziShUQNOelv1C4tYr0cjZ2IjgUf5Nwx4Rr+9+y5oKY+RextduYx9dWDrKLOJ7ONWR0v/FQbs0hm0ciqcbQRz9JIjnhWvuD9nPt4ir6htSu9w9fMlAwB596UoWaellrlLZRt8yE8ghfmXUpHdogky/n3QwKb+v7ZX55Jo1iIlpdKNodJT5qhaEgF93t6apq3LrbUGZukFOUrrw2JT1ZdupLWXj9I1ev8MQKnsvK3uEweG34TziE/L1EcKHI5zSAcuiYSomRcuL9xqGWm7ulcETIhTdQoOvzZ5ueVUM/Q1JvyRIX7UsKiFsIn+NcRfDGkZm2rrUl5d3wXw6WG16nqvWNJKmHFO/AOWSVHGAKIUIB8Ggl8krg0UatHiXWbuurr8RnbUiXqLqWx2c/KIni7Kj0VOJCTcKb2IyflwKms5BypHVKzblwdP0NPezHHqKnNO7lO+pBo+/Gy4VCOftk3k31HbUje3f0oxaxgzfYWQrkyCvhBkVS0Zw5ilJf+RicQW7nQR8pzdaagWRsCtnCi+YcBuyCH58RDiPj73EWsSN/Kj7DH9eOZOVyblJJKWjF+Hc3E0Z12FuYMvHg9rj5JCQvUsLGMT6KM/hznCQo0jmpJeACz2BrsREHcJ6OChYxVoMtv2Ac5OczBvndmtbBytIEprjKPmKyoEMRJ45ivkfeaIoZe/M5DHcaS2Z8wXcVVnnM+B5LJJofpRzSHd4pqvEzhS2NP8Y6TPwCs9FZMdf63zR1Xq7Lr2IU4Iv5eNsjFcu2EKnjOmQwSJVsjuZjj+XY3MyvODGfuthPtgGOecH4/9H36Coxm8kJ3Z7X49lVMwYe0rEgPbiD8pbQFXACp0RfCrVpco5ELE/xxKP7NUg/Hg2dw8pJKkmZYKG3luKjHssYAmSqPYbotOAzw+81zEs7o6/gADiOzOkj/ty4PijsYLeY+7JsPbwUsj1vvXG+nI/SRKDGbexjJU9AeNTd/RySUXqilHXNw0g2GBraE/zxYHlp/Vo+4AXk5KZdzZbAgxl++9EGdnlKJldLWcF+D2OaOa4HCyNTK2RgvAD+MNWg2jmHMOd1jBgKnEk4VeMU28N5tty7RrwjBLjD+BHLsia4GnB9LrHRwWlWyD1niOVWj8jZ2ZxHpDlOmSxbV5gN9janYKsKeNbr0PVSVmAtR6Yws8D55+0Uc/1v16NMjknLtkOnBRQyg/4K87kmgWhxBydjAYCeS4hWBvJUCHE9+PoaCw5Ee22lCauOK9wsjJdZiXureWM9P/4NEvVcB1Hh9WQh84AdxSF5FZxVvfkGc+GGMeaQHmKu+V04vO2vkfo9soLr8ZerfDxvtgcP63wNvgxRvuuBWWEaEccqOHg+J90TN7vw7opbj0MMGjT7XLzxQia4f4ldILZoXgSGxCsN+kETMESdM4Vgs7UWMSbhzEX+NpeT0CBpWlcoEEl51ZrcjlDuM5+F9oNZ3mdAR3v8r4HzIm4lFvVMTxLmLsueG7A9Lb0Val6z788rq+T6WX8x1bR9Wnqx2RvOftg3V1i5gECd6P+S/tztfOxk9wzY2BeeB3wV7/93A0A2QylmEWF/nkbZUP0P6Vp9B7Z/Z9M3pr+pWVBRs7bvzOKsvoXgOtot4aoChxEglIn2F/lGwz2Z3GHETJ+RazmJ7nYrWy4fPxb6skKRXFGsUxOuSS91I2EwWPkxwCEfWBbLI7e29TrIbSBm8lOAZMfw6U9PRVqlIAFi4YU1XxafAK98dsVLOotog8ng436PKh79AvZh7ZL9wmCLuW720A6TD70lVBEb3Ml6S/bYUgqxXv1CGI10K7mIOi9eINle8ZbCi8R5jtoV5zAySsS8WsQRax1AyjRMzkQ/wJK57FRO56qu1YIE867A6BW1mMQ6iAfq/q3eyWi2G8tw+CHW2ADz7d1pfRxYMpgK+JrHRAEja8D5InMPwJFYC7BK1t436m9fDPPjulyRCV1t/Ahli84B1TjkquWiypsN5hBaid7Q/9jnioQ28Hdm+2MD61anwq1ud6RC6ZUiaQfPfnsAMhtWJHurCxgz8OJpPGsFfOq7ecjqB34Mk5mrU6CNLPKpSBvv5thy8hBE0+OlYjwl1ly1SOlHh/6itH1eayqoOVFNRg/o1hr3kIQTmi4rGVyqD2/V06BC7b6CePeZW7+SAJMh9yE8pKbVDxvtds7TMYIpbLA+YFHb268ENAIMzto+uWyHaz+8HF0taYM58R22OfbkZevWi/Q3fiDc5jK8m97dGKbr9h1q6VDPMKoT69x4TiYFMl44EoebRN+Yav8K2dIvVHYtCv1Y2iHSEQPOPJ2t7JvcZgViwtssIHswqh6QEO3ie1JQQDcqz6sTRLlsFe5T11oWDMnpkhYQhr5wQZTjGvRu8AE+ozKdZnOU3+OvL5c9CRxyxnmg91QDJffRAJLP8oUbCxwWvixEKP0cwEH7n9/pKdhxFupsoGXtwCNl76bD9i8R+0IcvgaHszP6leBGBR+EmdwKU60dVn9SsXR+coE1cNDCDPWXlxvX6Tu/e0fbSZHW3ZK8wrXLsw+tKLL2Z0m7rwgMUKVRqbURGhrODE7ReXcU56/FNioW7V9N/SBYK3IEOUv1GyZSl9mBkfkr0JK+AwJbnEhlh/15X3YeWkT32dlcFzCy1WZlndFhWEWCIAESP8u407jLd5AtP0K5r+t1QRQsXyXWvflL338oti5shdpB4gGZ+09i5nRu6rTD56rgK8RD1+3fNh+CxT9XaJAEnKMi8cMhUtO0aHeE+xZ/cL4GoU7RFn5f8iURVkd9fDeJmNv0QlPMQ4xvDjiWArQ4bx28GhYZ7CF8MPCuDkAZh9KF3eERWxWaspotBvZa5iTN1T+c0ZMGEWUB2rsLBKFgnqD1Lhhq6UWjFeeME9R9PFLNRQR6UIJo1MQomhm929Mt2FFOviq6bNGru9TWivH4pGgA3qZ30uEWgHC5YBuLCZ48vzCDKrOc0/9YwmBUwSENXl7YEseIX3WNVJA7GkLq5HzWx4ovQyr/WnAULrh0PYkd9stnQ/XGFBZ8G5Ar6LvVrL5j2CupxDXASDHmKJVyqcbcU6g5D7FR1jvhU1W38e0csNLa/52zBVh8fcidennY99F1ggIb47jorycqBIqVmia8ZQn6ZLg+NOyl0y6yANIdsTipTarF89EaptrcdEsy+Q1q3X1A+RR8KNpgDfVGYtZY8XYr9btosYdUhdcySx5AFuAOT90u+5wSUeypSlXZmdwGZPUtWwdod5HwdO5JCIoa73AzAf1rzZOgLPYDIzBzjVox5w3xgNZl50mFgY0rwIWnhkPuh/kDxm98EgC6kYDsGdMF3lDBqi/l4tzI3av+X8l8tJqoBwit/04qN3z/eYUD/bFVB1EG9miuA2vwm4CmnhnmxKVJJLqkn9ohEAnVE3ol5VPszlsFK8YV8qqCC2f8e5M5FeVZ0rB5lCxodSqTTa2VrQyruocrZer/aoktEwS2DkJbsfoUGjLGvN8k0OOVIZZrNDYL5nH3lAusXndDFvKAFwB1W+WzpJaR+VKCMVb6tTHUJb4Ax+Ynk3HAt84ulJySNwna4HeE8MB0KyBkMTJqk2OOBKMH74Vtpz2cPGWXM2A0tDNBNqZcFHauVBPUizfXma+25zT/AIT9GJ/PyYBjK2X2xzoYWWGAC+XCJfSpVEqCoLTDUkZ0MEFNr057ztsax5S4/r5bI9NLfeq8ATXHmkl9WJp4Mwq651901PZ3qmyrEobxWoQMXxmi9pFOERMF9+c53YvyHds7mlmN4dIpTgY+hwZ0OJjwvmIiq4r0p04CMTHfNJ8Hk3CZKBij0pNn/tCSZhduUuq0yl/B5IBnK4ZcOQUFhUvqXA0sEPPeCVJBB9G13Rdk/POTakDNvSnAKVbbQH+O5hrZbBG5Xdtp5R7scRmP7McSHQqG+wThu3QKbPfef3995WzHKob3cM0iKR9teg8HTEMGABCKTHiJuEJYR3pBvpzHmsSmG8PYG2AaSwGatJW9HebCWHbYCVIW5KZU4jvlEc8UqKFM+1JcYCFgSZR09NOMBNi7YQy8KXGfH8STGqOT7FQBxWojIdFnQk4njijEaDZfdMS7s3g7OMKdN0n0NPLz98LnqkjzmzWlo8HT3q2n/L0HRDr2w7nalh3ZLzUzAMyKvZowOSlc8dGzypCaQG2MUnPGNV3lO9djZWRxzgKNtVkVKjEi70dFCix37YOzPv0lHhd4Gy9pQyjoBtURMz7VjEyg3iehi5odMm53bMVAVTb9O13UukGmOG7mHJfsalTahSbQt8rTZv0lskJ6nuGdVYSQ+Cg0lhPUhPP77mRVVuL5OwzBfPYofKCa56j+AICrzABtnQBTxRP2nqFF0tR288u1PNF4+oBrcyNQdAhZaLhMUsKJZg2BCyYoGIYZ8OcSePOjY5Yio41IyzyhORrY+qU9VLg8oIYGIuso3RX2eo6kqq/6YJfnkINFz3AFjgJCMHZNA5TbHBC9WPtjE8nLQ99cn2tTcBPG+MTlq1wTr73zpYB16svVVQE30wfpAnGAm5MgTiloLr5fVqkHodVsCe82KqJCKbrrakg6EwdECiJp+uzZfHPMKuU9vHfdn9FeeGS0QFpSwMudFrwpCcKqXhNmZmuyXofuAOHH/pmHFYw0V8BxUEza3a3ZSdy0XNQGxHdkGLXhx+swFEZ2KfVzzlZVR7EsXbu95MVBrxIN6CitpKgvFO5qFBoJecyv+Gh/ZpHA/v9D2PuSneeQKiiEz9y9x3zV9hN0jFlkIfavI+YKP1TWkVaxdrp5OraFbyc0vZ/X3BELs5ccPakCykBY+1oLDtXAj+YfH0oEbEL3J4GZMh7Jo34vextHSmxj3HV78d0vX7D1fgg7EBfivQuDpXZI4e/f0kobD4J630gHt9bRD5D0W6ab5evGeBLCCu8e6ZKeeSu7UxtmLwBuQZ2gKU15kWYxeJk5xWXWt6Ax5YSDpPIHxPSTcT1Ei0SA9aq4DR/mMiI3Oz32x1H179NpPeMd8bfQNX4pjjmMHa1Nr08IuScCMKSsNuvK4Vc38l2MfDXztEJ7jjRyy6YueL7D8Sag1JoZUlHXdq7XouiynThNnk4OwkKlfsIZ7iC2Ti6eu/nkkQXiEMyX2/UlHIwFlTSlZp1VREGujaVacmrG4s9sQHDf/mP3b2QDOM9W3WBv+UyOUBi0lwsDes9uQsO5qCqVh98oyh0pykybAmsrf/ge1HvNmE57h9G50E94wzXuCi9K0c4ssWbaQp7W4sNjQFCyZ/raqC/FurKEsL4ZjPKKxY5thbkLon6CRnClzSdiVzQYP2gGipQSkOI4Gy4/d+aSemKLGu1pv+3/Tx5qZjNbiabph2G4HqXYvDhC1a1ru8lk7j9C38AAXNUp9FnBqbTMNsg45ZbgXrENV70RJXwjmjn4yDSym53EWtCOIeDE3lOQc14lGvrBFIBwNU4OOBS/Xd8fF+NPOp18MYmYQKziC+Q17WmYF1P7CyJ4k5WO1aLy+2EHVnAEgcFTrRLdCH4zd3KQbBPBKyaJe0FhO5q1MpzoW0IY3G15J2GSy62iMoSIfWdXEBj/ptfmxN9I44cw0nLjO+SRhPcgx9VSehs2T9tRfSy+tEvtesnWSSp6H6UwpsYOgtyhJfTg+UWRb/NQyW4Xs0SJUdZLo1VTi+ESGVJF5Y9F3JDY9V6V3FiG6j1i5QqIERjLMtxu/NpCkBhR35y6O+y1iiPb8iAFNMsw+ooD//9wS/9s0M77i1KSvIZwRzM5iyleerm81aKoDh7Sp3dnu5ahUQ3Rbl/y2j8HFI4SYmn8qzOkNUzvCBigCf/iwj9ho/P/OVcMcvMx+dcLtpLxAe2ITkS6StfbeYrfaIhAaYMagg4A2Y8uGCKTrP4XTKoACMhdhGpFNUaOyvmkMTvi3yqRlq+oGx6a9KbPYwKmw2+E/nYa5eUZn3iqYAaTf1Dj5RhtiHCfF+6wP2xepKtWe8Bp4c6ee8uEA+gfco+qxvZ7YAFYeM3IhyHlJ5dA4pvKxoOS/TDl70t8I+pxBBbsOVRl1OvBX+4PFN0YI2IG6w9c15ruMIzeEnKG59ws6vTJwCPuKCwM54Ncs7dDH/wSNEyl5N6zpGqz9PtduCJa6clmHuTUo2Er6SbRaMe3GUwJJYoNTjARQCgheSyAwSLZ9g6myNxZ4ZF61U54qN6ZUc9udOq6jFLK7inCYNazT9rvUQ7soHXC8pvYOHY9fYelBuxqAApp2oRXzmpUUaXUXRCfdAyjm4wa9vKRkVxUkVEL+5152xJ9jjAqkaeQkW5vRzW/1Vf/UaXSSKPeWJvBy/VG0zPTEUZNXFnC3Q7+0sEr9izakOHLc0w6ggZkH6N4EXh37xBMsC6wyVZl64fM3nPXzkZsTmsGQYeL9oT4PZs0k25rjN60CkWHjjvgH1OAihooHMqo/shRxFEfTbxoEed0Up5L0J4QJomdW2nFx/o5fWlyEkBi8ZSw4F2dDEgTIAVtGIHexw0yO2Ee8T2r+ZYwfa0k4PHL3cqXEwqA9ihME/jqYxJE5C53HIPxIqex0tmpZ7mOvBdj+25ZN7gJRV17ORMo=`
const testKey = "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9"
const testIV = "d58ce954203b7c9a9a9d467f59839249"

type FakeKeyGoverner struct{}

func (FakeKeyGoverner) GenerateContentKeyID(contentID []byte) []byte {
	h := md5.New()
	h.Write(contentID)
	return h.Sum(nil)

}
func (FakeKeyGoverner) GenerateContentKey(contentID []byte) []byte {
	return nil
}
func (FakeKeyGoverner) GenerateContentIV(contentID []byte) []byte {
	return nil
}

func (FakeKeyGoverner) GenerateContentKeySpec(contentID []byte, policyConfig map[string]string) (*[]ContentKeySpec, error) {
	cks := []ContentKeySpec{
		{
			KeyID:     "base64EncodedString",
			Key:       "base64EncodedString",
			IV:        "base64EncodedString",
			TrackType: "SD",
		},
	}
	return &cks, nil
}

func TestGetLicense(t *testing.T) {
	key, _ := hex.DecodeString(testKey)
	iv, _ := hex.DecodeString(testIV)

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC822,
	})
	logger.SetOutput(colorable.NewColorableStdout())

	keyGenerator := &FakeKeyGoverner{}

	wv := NewWidevineProxy(key, iv, "widevine_test", keyGenerator, logger)
	contentID := "fkj3ljaSdfalkr3j"
	resp, err := wv.GetLicense(contentID, testLicenseChallenge)
	assert.NoError(t, err)
	b, _ := json.Marshal(resp)
	logger.Debug(string(b))
	assert.Equal(t, resp.Status, "OK")
}

func TestGenerateSignature(t *testing.T) {

	payload := map[string]interface{}{
		"test":   "testing",
		"test2":  "testing2",
		"test3":  "testing3",
		"isTest": true,
	}
	jsonPayload, _ := json.Marshal(payload)

	key, _ := hex.DecodeString(testKey)
	iv, _ := hex.DecodeString(testIV)
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC822,
	})
	logger.SetOutput(colorable.NewColorableStdout())

	keyGenerator := &FakeKeyGoverner{}

	wv := NewWidevineProxy(key, iv, "widevine_test", keyGenerator, logger)

	sign, err := wv.generateSignature(jsonPayload)
	assert.NoError(t, err)
	expectedSignature, err := base64.StdEncoding.DecodeString("ga80QzRuUM+jnPcoR6UWs5TXrTQ2VgeYiu0FoqCNRH4=")
	assert.NoError(t, err)
	assert.Zero(t, bytes.Compare(sign, expectedSignature))

}
