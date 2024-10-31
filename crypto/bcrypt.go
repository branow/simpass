package crypto

import "golang.org/x/crypto/bcrypt"

// BCryptHasher is a struct that implements hashing and coparing
// methods using bcrypt with cost [BCryptCost]. It uses
// [golang.org/x/crypto/bcrypt] package.
type BCryptHasher struct{}

const BCryptCost = 12

// Hash hashes the given password. See
// [golang.org/x/crypto/bcrypt.GenerateFromPassword].
// The returned error could be ignored.
func (bch BCryptHasher) Hash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, BCryptCost)
}

// Compare compares the given password with the hash. See
// [golang.org/x/crypto/bcrypt.CompareHashAndPassword].
func (bch BCryptHasher) Compare(password, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}
