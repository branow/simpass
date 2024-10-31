package crypto

import (
	"encoding/hex"
	"errors"
)

// Cipherhex is a wrapper around [Cipher] that works with strings
// in hex format instead of slices of bytes. Particularly, cipher key
// and cipher text are considered in hex format.
type CipherHex struct {
	Cipher Cipher
}

// GenerateKey generates a random 32-byte key in hex format.
// It is based on [Cipher.GenerateKey]
func (c CipherHex) GenerateKey() string {
	k := c.Cipher.GenerateKey()
	return hex.EncodeToString(k)
}

// AdjustKey adjusts the given key (does not have to be in hex)
// to the proper length and return the result in hex format.
// It is based on [Cipher.AdjustKey]
func (c CipherHex) AdjustKey(key string) string {
	bytes := c.Cipher.AdjustKey([]byte(key))
	return hex.EncodeToString(bytes)
}

// Encrypt encrypts the given plaintext with the hex format key
// and returns the ciphertext hex format too. The length of the key should
// be 32 bytes after decoding, otherwise an error will be returned.
// It is based on [Cipher.Encrypt]
func (c CipherHex) Encrypt(key, plaintext string) (string, error) {
	k, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	data, err := c.Cipher.Encrypt([]byte(k), []byte(plaintext))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// Decrypt decrypts the given ciphertext with the key that both
// must be in hex format and returns the plaintext. The length of the key should
// be 32 bytes after decoding, otherwise an error will be returned.
// It is based on [Cipher.Decrypt]
func (c CipherHex) Decrypt(key, ciphertext string) (string, error) {
	k, err1 := hex.DecodeString(key)
	ct, err2 := hex.DecodeString(ciphertext)
	err := errors.Join(err1, err2)
	if err != nil {
		return "", err
	}
	data, err := c.Cipher.Decrypt([]byte(k), ct)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
