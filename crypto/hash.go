package crypto

// Hasher defines signatures of hashing and hash matching methods.
type Hasher interface {

	// Hash hashes the given password
	Hash(password []byte) ([]byte, error)

	// CompareHex compares the given password with the hash.
	Compare(password, hash []byte) error
}
