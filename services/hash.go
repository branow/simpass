package services

import (
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// Hasher defines signatures of hashing and hash matching methods.
type Hasher interface {

	// HashHex hashes the given password and return result in hex format.
	HashHex(password string) (string, error)

	// Hash hashes the given password
	Hash(password []byte) ([]byte, error)

	// CompareHex compares the given password with the hash in hex format
	// and if they match, returns nil otherwise an error is returned.
	CompareHex(password, hash string) error

	// CompareHex compares the given password with the hash
	// and if they match, returns nil otherwise an error is returned.
	Compare(password, hash []byte) error
}

// BCryptHasher is a struct that implements Hasher interface using bcrypt with
// cost [BCryptCost]. It is based on [golang.org/x/crypto/bcrypt].
type BCryptHasher struct{}

const BCryptCost = 12

// HashHex hashes the given password and return the hash in hex format.
// It is based on [BCryptHasher.Hash].
// The returned error could be ignored.
func (bch BCryptHasher) HashHex(password string) (string, error) {
	h, err := bch.Hash([]byte(password))
	return hex.EncodeToString(h), err
}

// Hash hashes the given password. See
// [golang.org/x/crypto/bcrypt.GenerateFromPassword].
// The returned error could be ignored.
func (bch BCryptHasher) Hash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, BCryptCost)
}

// CompareHex compares the given password with the hash in hex format.
// It is based on [BCryptHasher.Compare].
func (bch BCryptHasher) CompareHex(password, hash string) error {
	h, err := hex.DecodeString(hash)
	if err != nil {
		return err
	}
	return bch.Compare([]byte(password), h)
}

// Compare compares the given password with the hash. See
// [golang.org/x/crypto/bcrypt.CompareHashAndPassword].
func (bch BCryptHasher) Compare(password, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}
