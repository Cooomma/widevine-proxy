package widevineproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	return origData[:(len(origData) - int(origData[len(origData)-1]))]
}

// AESCBCEncrypt is given key, iv to encrypt the plainText in AES CBC way.
func AESCBCEncrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	if len(plainText)%aes.BlockSize != 0 {
		plainText = PKCS5Padding(plainText, block.BlockSize())
	}
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)

	return ciphertext, nil

}

// AESCBCDecrypt is given key, iv to decrypt the cipherText in AES CBC way.
func AESCBCDecrypt(key, iv, cipherText []byte) ([]byte, error) {

	if len(cipherText) == 0 {
		panic("ciphertext can't be plain")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)
	if len(cipherText)%aes.BlockSize == 0 {
		return plainText, nil
	}
	return PKCS5UnPadding(plainText), nil
}
