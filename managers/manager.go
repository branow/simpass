package managers

import (
	"errors"
	"regexp"
	"fmt"
	"encoding/json"

	"github.com/branow/simpass/models"
)

var (
	ErrEmptyDataPairName        = errors.New("data pair name is empty")
	ErrDataPairIsAlreadyPresent = errors.New("data pair with the name is already present in the data unit in the file")
	ErrDataPairNotFound         = errors.New("data pair not found in the data unit in the file")
)

type DataUnitEncryptionErr struct {
	Cause error
}

func (e DataUnitEncryptionErr) Error() string {
	return fmt.Sprintf("data unit encryption error: %v", e.Cause)
}

func (e DataUnitEncryptionErr) Unwrap() error {
	return e.Cause
}

type DataUnitDecryptionErr struct {
	Cause error
}

func (e DataUnitDecryptionErr) Error() string {
	return fmt.Sprintf("data unit decryption error: %v", e.Cause)
}

func (e DataUnitDecryptionErr) Unwrap() error {
	return e.Cause
}

type WrongPasswordErr struct {
	Cause error
}

func (e WrongPasswordErr) Error() string {
	return fmt.Sprintf("wrong password: %v", e.Cause)
}

func (e WrongPasswordErr) Unwrap() error {
	return e.Cause
}

type NillErr struct {
	Name string
}

func (e NillErr) Error() string {
	return fmt.Sprintf("%q is nill", e.Name)
}

func NewSimpleManager(storage Storage, cipher Cipher, hasher Hasher) *SimpleManager {
	errs := []error{}	
	if storage == nil {
		errs = append(errs, NillErr{Name: "storage"})
	}
	if cipher == nil {
		errs = append(errs, NillErr{Name: "cipher"})
	}
	if hasher == nil {
		errs = append(errs, NillErr{Name: "hasher"})
	}
	err := errors.Join(errs...)
	if err != nil {
		panic(err)
	}

	return &SimpleManager{
		storage: storage,
		cipher: cipher,
		hasher: hasher,
	}
}

type SimpleManager struct {
	storage Storage
	cipher  Cipher
	hasher  Hasher
}

func (m SimpleManager) AddDataUnit(path, key string, unit models.DataUnit) error {
	encPairs, err := m.encryptPairs(key, unit.Pairs)
	if err != nil {
		return wrapDataUnitErr(path, unit.Name, err)
	}
	return m.storage.AddDataUnit(path, unit.Name, encPairs)
}

func (m SimpleManager) DeleteDataUnits(path string, names ...string) error {
	return m.storage.DeleteDataUnits(path, names...)
}

func (m SimpleManager) AddDataPairs(path, key, unitName string, pairs ...models.DataPair) error {
	value, err := m.storage.GetDataUnit(path, unitName)
	if err != nil {
		return err
	}
	pairsMap, err := m.decryptPairs(key, value)
	if err != nil {
		return wrapDataUnitErr(path, unitName, err)
	}
	errs := []error{}
	for _, p := range pairs {
		if p.Name == "" {
			errs = append(errs, wrapDataPairErr(path, unitName, p.Name, ErrEmptyDataPairName))
			continue
		}
		if _, ok := pairsMap[p.Name]; ok {
			errs = append(errs, wrapDataPairErr(path, unitName, p.Name, ErrDataPairIsAlreadyPresent))
			continue
		}
		pairsMap[p.Name] = p.Value
	}
	updValue, err := m.encryptPairs(key, pairsMap)
	if err != nil {
		return wrapDataUnitErr(path, unitName, err)
	}
	err = m.storage.UpdateDataUnit(path, unitName, updValue)
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

func (m SimpleManager) UpdateDataPair(path, key, unitName string, pair models.DataPair) error {
	value, err := m.storage.GetDataUnit(path, unitName)
	if err != nil {
		return err
	}
	pairsMap, err := m.decryptPairs(key, value)
	if err != nil {
		return wrapDataUnitErr(path, unitName, err)
	}
	if _, ok := pairsMap[pair.Name]; !ok {
		return wrapDataPairErr(path, unitName, pair.Name, ErrDataPairNotFound)
	}
	pairsMap[pair.Name] = pair.Value
	updValue, err := m.encryptPairs(key, pairsMap)
	if err != nil {
		return wrapDataUnitErr(path, unitName, err)
	}
	return m.storage.UpdateDataUnit(path, unitName, updValue)
}

func (m SimpleManager) DeleteDataPairs(path, key, unitName string, pairs ...string) error {
	value, err := m.storage.GetDataUnit(path, unitName)
	if err != nil {
		return err
	}
	pairsMap, err := m.decryptPairs(key, value)
	if err != nil {
		return wrapDataUnitErr(path, unitName, err)
	}
	errs := []error{}
	for _, p := range pairs {
		if _, ok := pairsMap[p]; ok {
			delete(pairsMap, p)
		} else {
			errs = append(errs, wrapDataPairErr(path, unitName, p, ErrDataPairNotFound))
		}
	}
	updValue, err := m.encryptPairs(key, pairsMap)
	if err != nil {
		return wrapDataUnitErr(path, unitName, err)
	}
	err = m.storage.UpdateDataUnit(path, unitName, updValue)
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

func (m SimpleManager) GetCryptKey(path, password string) (string, error) {
	passwordHash, err := m.storage.GetPasswordHash(path)
	if err != nil {
		return "", err
	}
	err = m.hasher.Compare(password, passwordHash)
	if err != nil {
		return "", wrapFileErr(path, WrongPasswordErr{Cause: err})
	}
	encCryptKey, err := m.storage.GetCryptKey(path)
	if err != nil {
		return "", err
	}
	passwordKey := m.cipher.AdjustKey(password)
	cryptKey, err := m.cipher.Decrypt(passwordKey, encCryptKey)
	if err != nil {
		return "", wrapFileErr(path, err)
	}
	return cryptKey, nil
}

func (m SimpleManager) CreateStorageFile(path, password string) error {
	passKey := m.cipher.AdjustKey(password)
	dataKey := m.cipher.GenerateKey()
	encKey, err := m.cipher.Encrypt(passKey, dataKey)
	if err != nil {
		return wrapFileErr(path, err)
	}
	hash, err := m.hasher.Hash(password)
	if err != nil {
		return wrapFileErr(path, err)
	}
	return m.storage.CreateStorageFile(path, hash, encKey)
}

func (m SimpleManager) Search(path, key string, unitRegexp, pairRegexp *regexp.Regexp) ([]models.DataUnit, error) {
	unitsMap, err := m.storage.GetDataUnits(path)
	if err != nil {
		return nil, err
	}
	units := make([]models.DataUnit, 0, len(unitsMap))
	for unitName, unitValue := range unitsMap {
		if unitRegexp.Match([]byte(unitName)) {
			unit := models.DataUnit{Name: unitName, Pairs: map[string]string{}}
			pairs, err := m.decryptPairs(key, unitValue)
			if err != nil {
				return nil, wrapDataUnitErr(path, unitName, err)
			}

			for k, v := range pairs {
				if pairRegexp.Match([]byte(k)) {
					unit.Pairs[k] = v
				}
			}
			units = append(units, unit)
		}
	}
	return units, nil
}

func (m SimpleManager) decryptPairs(key, value string) (map[string]string, error) {
	jsonPairs, err := m.cipher.Decrypt(key, value)
	if err != nil {
		return nil, DataUnitDecryptionErr{Cause: err}
	}
	pairs := map[string]string{}
	err = json.Unmarshal([]byte(jsonPairs), &pairs)
	if err != nil {
		return nil, DataUnitDecryptionErr{Cause: err}
	}
	return pairs, nil
}

func (m SimpleManager) encryptPairs(key string, pairs map[string]string) (string, error) {
	jsonPairs, err := json.Marshal(pairs)
	if err != nil {
		return "", DataUnitEncryptionErr{Cause: err}
	}
	encPairs, err := m.cipher.Encrypt(key, string(jsonPairs))
	if err != nil {
		return "", DataUnitEncryptionErr{Cause: err}
	}
	return encPairs, nil
}

func wrapFileErr(file string, cause error) error {
	return fmt.Errorf("%w: %q=%q", cause, "file", file)
}

func wrapDataUnitErr(file, dataUnit string, cause error) error {
	return fmt.Errorf("%w: %q=%q %q=%q", cause, "file", file, "data unit", dataUnit)
}

func wrapDataPairErr(file, dataUnit, dataPair string, cause error) error {
	return fmt.Errorf("%w: %q=%q %q=%q %q=%q", cause, "file", file, "data unit", dataUnit, "data pair", dataPair)
}
