package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// Cipher defines signatures of key generation, encryption and
// decryption methods.
type Cipher interface {

	// GenerateKeyHex generates random key in hex format
	GenerateKeyHex() string

	// GenerateKey generates random key
	GenerateKey() []byte

	// AdjustKeyHex adjusts the given key to the proper length and return it
	// in hex format.
	AdjustKeyHex(key string) string

	// AdjustKey adjusts the given key to the proper length.
	AdjustKey(key []byte) []byte

	// EncryptHex encrypts the given plaintext with the key in hex format
	// and returns a ciphertext in hex format.
	EncryptHex(key, plaintext string) (string, error)

	// Encrypt encrypts the given plaintext with the key and returns
	// a ciphertext.
	Encrypt(key, plaintext []byte) ([]byte, error)

	// DecryptHex decrypts the given ciphertext in hex format with the key
	// in hex format and return a plaintext.
	DecryptHex(key, ciphertext string) (string, error)

	// Decrypt decrypts the given ciphertext with the ky and returns
	// a plaintext.
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

// AES256GCMCipher is a struct that implements Cipher interface using
// AES256 cipher with GCM mode.
type AES256GCMCipher struct{}

// The required length of a key
const AES256KeyLen = 32

// GenerateKeyHex generates a random 32-byte key in hex format.
// It is based on [AES256GCMCipher.GenerateKey]
func (c AES256GCMCipher) GenerateKeyHex() string {
	k := c.GenerateKey()
	return hex.EncodeToString(k)
}

// GenerateKey generates a random 32 byte key
// using [rand.Reader]
func (c AES256GCMCipher) GenerateKey() []byte {
	key := make([]byte, AES256KeyLen)
	rand.Reader.Read(key)
	return []byte(key)
}

// AdjustKeyHex adjusts the given key to the proper length and return it
// in hex format.
// It is based on [AES256GCMCipher.AdjustKey]
func (c AES256GCMCipher) AdjustKeyHex(key string) string {
	bytes := c.AdjustKey([]byte(key))
	return hex.EncodeToString(bytes)
}

// AdjustKey adjusts the given key to the cipher key length [AES256KeyLen].
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

// EncryptHex encrypts the given plaintext with the hex format key
// and returns the ciphertext hex format too. The length of the key should
// be 32 bytes after decoding, otherwise an error will be returned.
// It is based on [AES256GCMCipher.Encrypt]
func (c AES256GCMCipher) EncryptHex(key, plaintext string) (string, error) {
	k, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	data, _ := c.Encrypt([]byte(k), []byte(plaintext))
	return hex.EncodeToString(data), nil
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

// DecryptHex decrypts the given ciphertext with the key that both
// must be in hex format and returns the plaintext. The length of the key should
// be 32 bytes after decoding, otherwise an error will be returned.
// It is based on [AES256GCMCipher.Decrypt]
func (c AES256GCMCipher) DecryptHex(key, ciphertext string) (string, error) {
	k, err1 := hex.DecodeString(key)
	ct, err2 := hex.DecodeString(ciphertext)
	err := errors.Join(err1, err2)
	if err != nil {
		return "", err
	}
	data, err := c.Decrypt([]byte(k), ct)
	return string(data), err
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
