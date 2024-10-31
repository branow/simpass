package crypto

import "encoding/hex"

// HasherHex is a wrapper over [Hasher] that works with strings
// in hex format instead of slices of bytes.
type HasherHex struct {
	Hasher Hasher
}

// Hash hashes the given password and return the hash in hex format.
// The returned error could be ignored.
func (h HasherHex) Hash(password string) (string, error) {
	hash, err := h.Hasher.Hash([]byte(password))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// Compare compares the given password with the hash, both in hex format.
// If the given password matches the given hash, the returned error is nil.
func (h HasherHex) Compare(password, hash string) error {
	ha, err := hex.DecodeString(hash)
	if err != nil {
		return err
	}
	return h.Hasher.Compare([]byte(password), ha)
}
