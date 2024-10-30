package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/branow/simpass/models"
)

func NewJsonStorage() *JsonStorage {
	return &JsonStorage{}
}

type JsonStorage struct{}

func (s JsonStorage) CreateStorageFile(path, passwordHash, cryptKey string) (err error) {
	if isExist(path) {
		return wrapFileErr(path, models.ErrFileAlreadyExists)
	}
	file, err := os.Create(path)
	if err != nil {
		return wrapFileErr(path, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data := jsonStruct{
		PasswordHash: passwordHash,
		CryptKey:     cryptKey,
	}
	return s.write(path, &data)
}

func (s JsonStorage) GetPasswordHash(path string) (string, error) {
	data, err := s.read(path)
	if err != nil {
		return "", err
	}
	return data.PasswordHash, nil
}

func (s JsonStorage) GetCryptKey(path string) (string, error) {
	data, err := s.read(path)
	if err != nil {
		return "", err
	}
	return data.CryptKey, nil
}

func (s JsonStorage) GetDataUnit(path, name string) (string, error) {
	units, err := s.GetDataUnits(path)
	if err != nil {
		return "", err
	}
	if len(units) == 0 {
		return "", wrapFileErr(path, models.ErrNoDataUnits)
	}
	unit, ok := units[name]
	if !ok {
		return "", wrapDataUnitErr(path, name, models.ErrDataUnitNotFound)
	}
	return unit, nil
}

func (s JsonStorage) GetDataUnits(path string) (map[string]string, error) {
	data, err := s.read(path)
	if err != nil {
		return nil, err
	}
	if data.DataUnits == nil {
		return nil, wrapFileErr(path, models.ErrNoDataUnits)
	}
	return data.DataUnits, nil
}

func (s JsonStorage) AddDataUnit(path, name, value string) error {
	return s.update(path, func(data *jsonStruct) error {
		if data.DataUnits == nil {
			data.DataUnits = map[string]string{}
		}
		if _, ok := data.DataUnits[name]; ok {
			return wrapDataUnitErr(path, name, models.ErrDataUnitIsAlreadyPresent)
		}
		data.DataUnits[name] = value
		return nil
	})
}

func (s JsonStorage) UpdateDataUnit(path, name, value string) error {
	return s.update(path, func(data *jsonStruct) error {
		if data.DataUnits == nil || len(data.DataUnits) == 0 {
			return wrapFileErr(path, models.ErrNoDataUnits)
		}
		if _, ok := data.DataUnits[name]; !ok {
			return wrapDataUnitErr(path, name, models.ErrDataUnitNotFound)
		}
		data.DataUnits[name] = value
		return nil
	})
}

func (s JsonStorage) DeleteDataUnits(path string, names ...string) error {
	errs := []error{}
	for _, name := range names {
		if err := s.DeleteDataUnit(path, name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s JsonStorage) DeleteDataUnit(path, name string) error {
	return s.update(path, func(data *jsonStruct) error {
		if data.DataUnits == nil || len(data.DataUnits) == 0 {
			return wrapFileErr(path, models.ErrNoDataUnits)
		}
		if _, ok := data.DataUnits[name]; !ok {
			return wrapDataUnitErr(path, name, models.ErrDataUnitNotFound)
		}
		delete(data.DataUnits, name)
		return nil
	})
}

type updateFileData func(data *jsonStruct) error

func (s JsonStorage) update(path string, upd updateFileData) error {
	data, err := s.read(path)
	if err != nil {
		return err
	}
	if err = upd(data); err != nil {
		return err
	}
	return s.write(path, data)
}

func (s JsonStorage) read(path string) (*jsonStruct, error) {
	if !isExist(path) {
		return nil, wrapFileErr(path, models.ErrFileDoesNotExist)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, wrapFileErr(path, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data := &jsonStruct{}
	err = json.NewDecoder(file).Decode(data)
	return data, err
}

func (s JsonStorage) write(path string, data *jsonStruct) error {
	if !isExist(path) {
		return wrapFileErr(path, models.ErrFileDoesNotExist)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return wrapFileErr(path, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "\t")
	return encoder.Encode(data)
}

type jsonStruct struct {
	PasswordHash string            `json:"password-hash"`
	CryptKey     string            `json:"crypt-key"`
	DataUnits    map[string]string `json:"data-units"`
}

func wrapFileErr(file string, cause error) error {
	return fmt.Errorf("%w: %q=%q", cause, "file", file)
}

func wrapDataUnitErr(file, dataUnit string, cause error) error {
	return fmt.Errorf("%w: %q=%q %q=%q", cause, "file", file, "data unit", dataUnit)
}

func isExist(file string) bool {
	_, err := os.Stat(file)
	return !os.IsNotExist(err)
}
