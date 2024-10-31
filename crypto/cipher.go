package crypto

// Cipher defines signatures of key generation, encryption and
// decryption methods.
type Cipher interface {

	// GenerateKey generates a random key
	GenerateKey() []byte

	// AdjustKey adjusts the given key to the proper length.
	AdjustKey(key []byte) []byte

	// Encrypt encrypts the given plaintext with the key and returns
	// a ciphertext.
	Encrypt(key, plaintext []byte) ([]byte, error)

	// Decrypt decrypts the given ciphertext with the ky and returns
	// a plaintext.
	Decrypt(key, ciphertext []byte) ([]byte, error)
}
