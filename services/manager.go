package services

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/branow/simpass/models"
)

func NewManagerImpl(storage models.Storage, cipher Cipher, hasher Hasher) models.Manager {
	return ManagerImpl{
		hasher:  hasher,
		cipher:  cipher,
		storage: storage,
	}
}

// ManagerImpl is an implementation of a [models.Manager] interface.
type ManagerImpl struct {
	storage models.Storage
	cipher  Cipher
	hasher  Hasher
}

func (m ManagerImpl) CreateStorageFile(path, password string) error {
	passKey := m.cipher.AdjustKeyHex(password)
	dataKey := m.cipher.GenerateKeyHex()
	encKey, err := m.cipher.EncryptHex(passKey, dataKey)
	if err != nil {
		return err
	}
	hash, err := m.hasher.HashHex(password)
	if err != nil {
		return err
	}
	return m.storage.CreateStorageFile(path, hash, encKey)
}

func (m ManagerImpl) GetCryptKey(path, password string) (string, error) {
	passwordHash, err := m.storage.GetPasswordHash(path)
	if err != nil {
		return "", err
	}
	err = m.hasher.CompareHex(password, passwordHash)
	if err != nil {
		if errors.Is(err, PasswordHashMismatchErr{}) {
			return "", models.WrongPasswordErr{Path: path}
		}
		return "", err
	}
	encKey, err := m.storage.GetCryptKey(path)
	if err != nil {
		return "", err
	}
	key := m.cipher.AdjustKeyHex(password)
	return m.cipher.DecryptHex(key, encKey)
}

func (m ManagerImpl) AddDataUnit(path, key string, unit models.DataUnit) error {
	if unit.Name == "" {
		return models.EmptyDataUnitNameErr{Path: path, Pairs: unit.Pairs}
	}
	encPairs, err := m.encryptPairs(key, unit.Pairs)
	if err != nil {
		return models.DataUnitEncryptionErr{Path: path, Unit: unit.Name, Cause: err}
	}
	return m.storage.AddDataUnit(path, unit.Name, encPairs)
}

func (m ManagerImpl) DeleteDataUnits(path string, names ...string) error {
	return m.storage.DeleteDataUnits(path, names...)
}

func (m ManagerImpl) AddDataPairs(path, key, unitName string, pairs ...models.DataPair) error {
	value, err := m.storage.GetDataUnit(path, unitName)
	if err != nil {
		return err
	}
	pairsMap, err := m.decryptPairs(key, value)
	if err != nil {
		return models.DataUnitDecryptionErr{Path: path, Unit: unitName, Cause: err}
	}
	errs := []error{}
	for _, p := range pairs {
		if p.Name == "" {
			errs = append(errs, models.EmptyDataPairNameErr{Path: path, Value: p.Value})
			continue
		}
		if _, ok := pairsMap[p.Name]; ok {
			errs = append(errs, models.DataPairAlreadyExistsErr{Path: path, Unit: unitName, Name: p.Name})
			continue
		}
		pairsMap[p.Name] = p.Value
	}
	updValue, err := m.encryptPairs(key, pairsMap)
	if err != nil {
		return models.DataUnitEncryptionErr{Path: path, Unit: unitName, Cause: err}
	}
	err = m.storage.UpdateDataUnit(path, unitName, updValue)
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

func (m ManagerImpl) UpdateDataPair(path, key, unitName string, pair models.DataPair) error {
	value, err := m.storage.GetDataUnit(path, unitName)
	if err != nil {
		return err
	}
	pairsMap, err := m.decryptPairs(key, value)
	if err != nil {
		return models.DataUnitDecryptionErr{Path: path, Unit: unitName, Cause: err}
	}
	if _, ok := pairsMap[pair.Name]; !ok {
		return models.DataPairDoesNotExistErr{Path: path, Unit: unitName, Name: pair.Name}
	}
	pairsMap[pair.Name] = pair.Value
	updValue, err := m.encryptPairs(key, pairsMap)
	if err != nil {
		return models.DataUnitEncryptionErr{Path: path, Unit: unitName, Cause: err}
	}
	return m.storage.UpdateDataUnit(path, unitName, updValue)
}

func (m ManagerImpl) DeleteDataPairs(path, key, unitName string, pairs ...string) error {
	value, err := m.storage.GetDataUnit(path, unitName)
	if err != nil {
		return err
	}
	pairsMap, err := m.decryptPairs(key, value)
	if err != nil {
		return models.DataUnitDecryptionErr{Path: path, Unit: unitName, Cause: err}
	}
	errs := []error{}
	for _, p := range pairs {
		if _, ok := pairsMap[p]; ok {
			delete(pairsMap, p)
		} else {
			errs = append(errs, models.DataPairDoesNotExistErr{Path: path, Unit: unitName, Name: p})
		}
	}
	updValue, err := m.encryptPairs(key, pairsMap)
	if err != nil {
		return models.DataUnitEncryptionErr{Path: path, Unit: unitName, Cause: err}
	}
	err = m.storage.UpdateDataUnit(path, unitName, updValue)
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

func (m ManagerImpl) Search(path, key string, unitRegexp, pairRegexp *regexp.Regexp) ([]models.DataUnit, error) {
	unitsMap, err := m.storage.GetDataUnits(path)
	if err != nil {
		return nil, err
	}
	units := make([]models.DataUnit, 0, len(unitsMap))
	errs := []error{}
	for unitName, unitValue := range unitsMap {
		if unitRegexp.Match([]byte(unitName)) {
			unit := models.DataUnit{Name: unitName, Pairs: map[string]string{}}
			pairs, err := m.decryptPairs(key, unitValue)
			if err != nil {
				err = models.DataUnitDecryptionErr{Path: path, Unit: unitName, Cause: err}
				errs = append(errs, err)
				continue
			}
			for k, v := range pairs {
				if pairRegexp.Match([]byte(k)) {
					unit.Pairs[k] = v
				}
			}
			units = append(units, unit)
		}
	}
	return units, errors.Join(errs...)
}

func (m ManagerImpl) decryptPairs(key, value string) (map[string]string, error) {
	jsonPairs, err := m.cipher.DecryptHex(key, value)
	if err != nil {
		return nil, err
	}
	pairs := map[string]string{}
	err = json.Unmarshal([]byte(jsonPairs), &pairs)
	if err != nil {
		return nil, err
	}
	return pairs, nil
}

func (m ManagerImpl) encryptPairs(key string, pairs map[string]string) (string, error) {
	jsonPairs, err := json.Marshal(pairs)
	if err != nil {
		return "", err
	}
	return m.cipher.EncryptHex(key, string(jsonPairs))
}
