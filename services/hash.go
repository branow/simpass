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

	// CompareHex compares the given password with the hash in hex format.
	// If there is a mismatch, it returns [PasswordHashMismatch] error,
	// otherwise nil
	CompareHex(password, hash string) error

	// CompareHex compares the given password with the hash.
	// If there is a mismatch, it returns [PasswordHashMismatch] error,
	// otherwise nil
	Compare(password, hash []byte) error
}

type PasswordHashMismatch struct{}

func (e PasswordHashMismatch) Error() string {
	return "the password does not match the hash"
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
	err := bcrypt.CompareHashAndPassword(hash, password)
	if err != nil {
		if err.Error() == bcrypt.ErrMismatchedHashAndPassword.Error() {
			return PasswordHashMismatch{}
		}
	}
	return err
}
