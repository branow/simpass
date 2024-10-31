package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// AES256GCMCipher implements encrypting, decrypting, and key generating methods using
// AES256 cipher with GCM mode.
type AES256GCMCipher struct{}

// The required length of a key
const AES256KeyLen = 32

// GenerateKey generates a random 32 byte key
// using [rand.Reader]
func (c AES256GCMCipher) GenerateKey() []byte {
	key := make([]byte, AES256KeyLen)
	rand.Reader.Read(key)
	return []byte(key)
}

// AdjustKey adjusts the given key to the cipher key length [AES256KeyLen].
// If the key length is lower than required, it fills the gap with zeros.
// If the key length is longer, it adds the extra bytes to the main bytes,
// according to the index module.
func (c AES256GCMCipher) AdjustKey(key []byte) []byte {
	fitKey := make([]byte, 32)
	copy(fitKey, key)
	if len(key) > AES256KeyLen {
		for i := AES256KeyLen; i < len(key); i++ {
			j := i % AES256KeyLen
			fitKey[j] += key[i]
		}
	}
	return fitKey
}

// Encrypt encrypts the given plaintext and returns the ciphertext.
// The length of the key should be 32 bytes.
// The first part of the returned ciphertext slice is the nonce.
func (c AES256GCMCipher) Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != AES256KeyLen {
		return nil, KeyLengthErr{ExpectedLen: AES256KeyLen, ActualLen: len(key)}
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Reader.Read(nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext and returns the plaintext.
// The length of the key should be 32 bytes.
// The first part of the given ciphertext slice must contain a nonce.
func (c AES256GCMCipher) Decrypt(key []byte, ciphertext []byte) (_ []byte, err error) {
	if len(key) != AES256KeyLen {
		return nil, KeyLengthErr{ExpectedLen: AES256KeyLen, ActualLen: len(key)}
	}
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	defer func() {
		if v := recover(); v != nil {
			err = errors.New(v.(string))
		}
	}()
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

type KeyLengthErr struct {
	ExpectedLen int
	ActualLen   int
}

func (e KeyLengthErr) Error() string {
	return fmt.Sprintf("key length must be %d bytes, but it is %d", e.ExpectedLen, e.ActualLen)
}
