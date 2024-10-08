package models

import (
	"fmt"
	"regexp"
)

// Manager provides methods for working with storage files
// (files that keep confidential information and follow proper
// format).
type Manager interface {

	// CreateStorageFile creates a storage file at the given path
	// for the user's sensitive data. There is also the hash of
	// the given password and a randomly generated key for encrypting
	// and decrypting of user data in encrypted form. The password
	// and the key are both stored in hex format in the file.
	CreateStorageFile(path, password string) error

	// GetCryptKey parses the storage file at the given path and
	// extracts the key for user data encryption/decryption.
	// If the given password does not match the hash in the file,
	// the [WrongPasswordErr] is returned.
	GetCryptKey(path, password string) (string, error)

	// AddDataUnits adds a new data unit to the given storage file.
	// The unit data name must be not empty otherwise it causes
	// [EmptyDataUnitNameErr]. The key is used for encryption pairs
	// of sensitive information of the unit and there must be one key
	// for all data units per file.
	AddDataUnit(path, key string, unit DataUnit) error

	// DeleteDataUnits removes the data units with the given name
	// from the file at the given path.
	DeleteDataUnits(path string, names ...string) error

	// AddDataPairs adds the given data pairs to the data unit
	// with the given name at the given path. The method tries
	// to add every data pair, except for those whose names are empty
	// or the pairs with such a name in the data unit already present.
	// Both mentioned cases cause errors: [EmptyDataPairNameErr]
	// and [DataPairAlreadyExistsErr] accordingly.
	AddDataPairs(path, key, unitName string, pairs ...DataPair) error

	// UpdateDataPair updates the data pair with the given name
	// by the given value in the data unit at the path. If there is
	// no data pair with such a name, it returns [DataPairDoesNotExistErr]
	// error.
	UpdateDataPair(path, key, unitName string, pair DataPair) error

	// DeleteDataPairs removes the data pairs with the given name
	// from the data unit at the path. The method tries to
	// remove every specified data pair, except for those which
	// do not present in the data unit. For every absent pair,
	// an [DataPairDoesNotExistsErr] error is returned.
	DeleteDataPairs(path, key, unitName string, pairs ...string) error

	// Search searches the data pairs whose names match the given
	// pair regexp and the names of data units to which they
	// belong match the given unit regexp at the specified path.
	Search(path, key string, unitRegexp, pairRegexp *regexp.Regexp) ([]DataUnit, error)
}

type DataUnit struct {
	Name  string
	Pairs map[string]string
}

type DataPair struct {
	Name  string
	Value string
}

type WrongPasswordErr struct {
	Path string
}

func (e WrongPasswordErr) Error() string {
	return fmt.Sprintf("%s: wrong password", e.Path)
}

type DataUnitEncryptionErr struct {
	Path  string
	Unit  string
	Cause error
}

func (e DataUnitEncryptionErr) Error() string {
	return fmt.Sprintf("%s: data unit '%s' encryption error: %v", e.Path, e.Unit, e.Cause)
}

type DataUnitDecryptionErr struct {
	Path  string
	Unit  string
	Cause error
}

func (e DataUnitDecryptionErr) Error() string {
	return fmt.Sprintf("%s: data unit '%s' decryption error: %v", e.Path, e.Unit, e.Cause)
}

type DataPairDoesNotExistErr struct {
	Path string
	Unit string
	Name string
}

func (e DataPairDoesNotExistErr) Error() string {
	return fmt.Sprintf("%s:%s: data pair with the key (%s) does not exist", e.Path, e.Unit, e.Name)
}

type DataPairAlreadyExistsErr struct {
	Path string
	Unit string
	Name string
}

func (e DataPairAlreadyExistsErr) Error() string {
	return fmt.Sprintf("%s:%s: data pair with the key (%s) already exists", e.Path, e.Unit, e.Name)
}

type EmptyDataUnitNameErr struct {
	Path  string
	Pairs map[string]string
}

func (e EmptyDataUnitNameErr) Error() string {
	return fmt.Sprintf("%s: data unit name with value '%v' is empty", e.Path, e.Pairs)
}

type EmptyDataPairNameErr struct {
	Path  string
	Value string
}

func (e EmptyDataPairNameErr) Error() string {
	return fmt.Sprintf("%s: data pair name with value '%s' is empty", e.Path, e.Value)
}
