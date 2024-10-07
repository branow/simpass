package storage

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/branow/simpass/models"
)

func NewJsonStorage() models.Storage {
	return JsonStorage{}
}

// A JsonStorage that implements interface [models.Storage] by using
// json data format.
type JsonStorage struct{}

func (s JsonStorage) CreateStorageFile(path, passwordHash, cryptKey string) error {
	if file, err := os.Open(path); err == nil {
		file.Close()
		return models.FileAlreadyExistsErr{Path: path}
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	file.Close()
	data := JsonStruct{
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
	notExistErr := models.DataUnitDoesNotExistErr{Path: path, Name: name}
	if units == nil {
		return "", notExistErr
	}
	unit, ok := units[name]
	if !ok {
		return "", notExistErr
	}
	return unit, nil
}

func (s JsonStorage) GetDataUnits(path string) (map[string]string, error) {
	data, err := s.read(path)
	if err != nil {
		return nil, err
	}
	return data.DataUnits, nil
}

func (s JsonStorage) AddDataUnit(path, name, value string) error {
	return s.update(path, func(data *JsonStruct) error {
		if data.DataUnits == nil {
			data.DataUnits = map[string]string{}
		}
		if _, ok := data.DataUnits[name]; ok {
			return models.DataUnitAlreadyExistErr{Path: path, Name: name}
		}
		data.DataUnits[name] = value
		return nil
	})
}

func (s JsonStorage) UpdateDataUnit(path, name, value string) error {
	return s.update(path, func(data *JsonStruct) error {
		notExistErr := models.DataUnitDoesNotExistErr{Path: path, Name: name}
		if data.DataUnits == nil {
			return notExistErr
		}
		if _, ok := data.DataUnits[name]; !ok {
			return notExistErr
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
	return s.update(path, func(data *JsonStruct) error {
		notExistErr := models.DataUnitDoesNotExistErr{Path: path, Name: name}
		if data.DataUnits == nil {
			return notExistErr
		}
		if _, ok := data.DataUnits[name]; !ok {
			return notExistErr
		}
		delete(data.DataUnits, name)
		return nil
	})
}

type updateFileData func(data *JsonStruct) error

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

func (s JsonStorage) read(path string) (*JsonStruct, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, models.FileDoesNotExistErr{Path: path}
		}
		return nil, err
	}
	defer file.Close()
	data := &JsonStruct{}
	err = json.NewDecoder(file).Decode(data)
	return data, err
}

func (s JsonStorage) write(path string, data *JsonStruct) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "\t")
	return encoder.Encode(data)
}

type JsonStruct struct {
	PasswordHash string            `json:"password-hash"`
	CryptKey     string            `json:"crypt-key"`
	DataUnits    map[string]string `json:"data-units"`
}
