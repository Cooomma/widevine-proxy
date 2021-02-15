package widevineproxy

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCBCEncryptAndDecrypt(t *testing.T) {
	var key = "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9"
	var iv = "d58ce954203b7c9a9a9d467f59839249"

	keyByteAry, _ := hex.DecodeString(key)
	ivByteAry, _ := hex.DecodeString(iv)

	plainText := "6368616e676520746869732070617373"

	crypted, err := AESCBCEncrypt(keyByteAry, ivByteAry, []byte(plainText))
	assert.NoError(t, err)

	decryptedPlainText, err := AESCBCDecrypt(keyByteAry, ivByteAry, crypted)
	assert.NoError(t, err)
	assert.Equal(t, []byte(plainText), decryptedPlainText)
}
