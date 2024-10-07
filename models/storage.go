package models

import "fmt"

type Storage interface {

	// CreateStorageFile creates a new file at the given path
	// and writes the given hash of a password and the encrypted
	// crypt(encrypting/decrypting) data key to it.
	//
	// If the file at the given path already exists, it returns
	// an error of the type [FileAlreadyExistsErr]. It returns
	// errors that happen during creating and writing as well.
	CreateStorageFile(path, passwordHash, cryptKey string) error

	// GetPasswordHash parses the given file and extracts
	// a hash of a password. If the file does not exist, it returns
	// an error of the type [FileDoesNotExistErr].
	GetPasswordHash(path string) (string, error)

	// GetCryptKey parses the given file and extracts a crypt key.
	// If the file does not exist, it returns an error of the
	// type [FileDoesNotExistErr].
	GetCryptKey(path string) (string, error)

	// GetDataUnit parses the given file and returns a data unit with
	// the given name if such one presents. Otherwise, it returns
	// an error of type [DataUnitDoesNotExistErr]
	GetDataUnit(path, name string) (string, error)

	// GetDataUnits parses the given file and returns all the data
	// units. If the file does not exist, it returns an error of the
	// type [FileDoesNotExistErr].
	GetDataUnits(path string) (map[string]string, error)

	// AddDataUnit updates the given file by adding a new data unit
	// with the given name and value. If the file does not exist,
	// it returns an error of the type [FileDoesNotExistErr]. If there
	// is already a data unit with such name, it returns an error of
	// type [DataUnitAlreadyExistErr]
	AddDataUnit(path, name, value string) error

	// AddDataUnit updates the given file by replacing the value of
	// the data unit with the given name for the given value. If the
	// file does not exist, it returns an error of the type
	// [FileDoesNotExistErr]. If there is not a data unit with
	// the given name, it returns an error of the type [DataUnitDoesNotExistErr]
	UpdateDataUnit(path, name, value string) error

	// DeleteDataUnit updates the given file by removing a data unit
	// with the given name if such one presents. Otherwise, it returns
	// an error of the type [DataUnitDoesNotExistErr]
	DeleteDataUnit(path, name string) error

	// DeleteDataUnits updates the given file by removing data units
	// with the given names. If some or all of the data units
	// are absent in the file, a joint error of errors of the type
	// [DataUnitDoesNotExistErr] is returned. The present data units
	// are removed, despite the absent ones.
	DeleteDataUnits(path string, names ...string) error
}

type FileDoesNotExistErr struct {
	Path string
}

func (e FileDoesNotExistErr) Error() string {
	return fmt.Sprintf("%s: File does not exist", e.Path)
}

type FileAlreadyExistsErr struct {
	Path string
}

func (e FileAlreadyExistsErr) Error() string {
	return fmt.Sprintf("%s: File already exists", e.Path)
}

type DataUnitDoesNotExistErr struct {
	Path string
	Name string
}

func (e DataUnitDoesNotExistErr) Error() string {
	return fmt.Sprintf("%s: Data unit with name '%s' does not exist", e.Path, e.Name)
}

type DataUnitAlreadyExistErr struct {
	Path string
	Name string
}

func (e DataUnitAlreadyExistErr) Error() string {
	return fmt.Sprintf("%s: Data unit with name '%s' already exists", e.Path, e.Name)
}
