package managers

type Cipher interface {
	GenerateKey() string
	AdjustKey(key string) string
	Encrypt(key, plaintext string) (string, error)
	Decrypt(key, ciphertext string) (string, error)
}

type Hasher interface {
	Hash(value string) (string, error)
	Compare(value, hash string) error
}

type Storage interface {

	CreateStorageFile(path, passwordHash, cryptKey string) error

	GetPasswordHash(path string) (string, error)

	GetCryptKey(path string) (string, error)

	GetDataUnit(path, name string) (string, error)

	GetDataUnits(path string) (map[string]string, error)

	AddDataUnit(path, name, value string) error

	UpdateDataUnit(path, name, value string) error

	DeleteDataUnit(path, name string) error

	DeleteDataUnits(path string, names ...string) error
}

