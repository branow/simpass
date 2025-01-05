package managers_test

import (
	"errors"
	"fmt"
	"testing"
	"regexp"

	. "github.com/branow/simpass/managers"
	"github.com/branow/simpass/models"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSimpleManager_CreateStorageFile(t *testing.T) {
	mCipherAdjustKey := mockedMethod{
		name: "AdjustKey",
		in:   []any{"password"},
		out:  []any{"adjust-password"},
	}
	mCipherGenerateKey := mockedMethod{
		name: "GenerateKey",
		in:   []any{},
		out:  []any{"crypt-key"},
	}
	mCipherEncryptErr := mockedMethod{
		name: "Encrypt",
		in:   []any{"adjust-password", "crypt-key"},
		out:  []any{"", errors.New("encryption error")},
	}
	mCipherEncrypt := mockedMethod{
		name: "Encrypt",
		in:   []any{"adjust-password", "crypt-key"},
		out:  []any{"encrypted-key", nil},
	}
	mHasherHashErr := mockedMethod{
		name: "Hash",
		in:   []any{"password"},
		out:  []any{"", errors.New("hashing error")},
	}
	mHasherHash := mockedMethod{
		"Hash",
		[]any{"password"},
		[]any{"hashed-password", nil},
	}
	mStorageCreateStorageFileErr := mockedMethod{
		name: "CreateStorageFile",
		in:   []any{"path", "hashed-password", "encrypted-key"},
		out:  []any{errors.New("creation file error")},
	}
	mStorageCreateStorageFile := mockedMethod{
		name: "CreateStorageFile",
		in:   []any{"path", "hashed-password", "encrypted-key"},
		out:  []any{nil},
	}
	data := []tab.Args{
		{
			"@encryption error",
			*NewSimpleManager(
				*newMockedStorage(),
				*newMockedCipher(mCipherAdjustKey, mCipherGenerateKey, mCipherEncryptErr),
				*newMockedHasher(),
			),
			"",
			mCipherAdjustKey.in[0],
			mCipherEncryptErr.out[1],
		},
		{
			"@hashing error",
			*NewSimpleManager(
				*newMockedStorage(),
				*newMockedCipher(mCipherAdjustKey, mCipherGenerateKey, mCipherEncrypt),
				*newMockedHasher(mHasherHashErr),
			),
			"",
			mCipherAdjustKey.in[0],
			mHasherHashErr.out[1],
		},
		{
			"@file creation error",
			*NewSimpleManager(
				*newMockedStorage(mStorageCreateStorageFileErr),
				*newMockedCipher(mCipherAdjustKey, mCipherGenerateKey, mCipherEncrypt),
				*newMockedHasher(mHasherHash),
			),
			mStorageCreateStorageFileErr.in[0],
			mCipherAdjustKey.in[0],
			mStorageCreateStorageFileErr.out[0],
		},
		{
			"@successful run",
			*NewSimpleManager(
				*newMockedStorage(mStorageCreateStorageFile),
				*newMockedCipher(mCipherAdjustKey, mCipherGenerateKey, mCipherEncrypt),
				*newMockedHasher(mHasherHash),
			),
			mStorageCreateStorageFileErr.in[0],
			mCipherAdjustKey.in[0],
			nil,
		},
	}
	test := func(t *testing.T, manager models.Manager, path, password string, eErr error) {
		aErr := manager.CreateStorageFile(path, password)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestSimpleManager_GetCryptKey(t *testing.T) {
	mStorageGetPasswordHashErr := mockedMethod{
		name: "GetPasswordHash",
		in:   []any{"path"},
		out:  []any{"", errors.New("getting password hash error")},
	}
	mStorageGetPasswordHash := mockedMethod{
		name: "GetPasswordHash",
		in:   []any{"path"},
		out:  []any{"password-hash", nil},
	}
	mHasherCompareErr := mockedMethod{
		name: "Compare",
		in:   []any{"password", "password-hash"},
		out:  []any{WrongPasswordErr{Cause: errors.New("not match")}},
	}
	mHasherCompare := mockedMethod{
		name: "Compare",
		in:   []any{"password", "password-hash"},
		out:  []any{nil},
	}
	mStorageGetCryptKeyErr := mockedMethod{
		name: "GetCryptKey",
		in:   []any{"path"},
		out:  []any{"", errors.New("getting crypt key error")},
	}
	mStorageGetCryptKey := mockedMethod{
		name: "GetCryptKey",
		in:   []any{"path"},
		out:  []any{"enc-crypt-key", nil},
	}
	mCipherAdjustKey := mockedMethod{
		name: "AdjustKey",
		in:   []any{"password"},
		out:  []any{"adjust-password"},
	}
	mCipherDecryptErr := mockedMethod{
		name: "Decrypt",
		in:   []any{"adjust-password", "enc-crypt-key"},
		out:  []any{"", errors.New("decryption error")},
	}
	mCipherDecrypt := mockedMethod{
		name: "Decrypt",
		in:   []any{"adjust-password", "enc-crypt-key"},
		out:  []any{"crypt-key", nil},
	}
	data := []tab.Args{
		{
			"@getting password hash error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetPasswordHashErr),
				*newMockedCipher(),
				*newMockedHasher(),
			),
			mStorageGetPasswordHash.in[0],
			mHasherCompare.in[0],
			"",
			mStorageGetPasswordHashErr.out[1],
		},
		{
			"@password doesn't match error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetPasswordHash),
				*newMockedCipher(),
				*newMockedHasher(mHasherCompareErr),
			),
			mStorageGetPasswordHash.in[0],
			mHasherCompare.in[0],
			"",
			mHasherCompareErr.out[0],
		},
		{
			"@getting crypt key error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetPasswordHash, mStorageGetCryptKeyErr),
				*newMockedCipher(),
				*newMockedHasher(mHasherCompare),
			),
			mStorageGetPasswordHash.in[0],
			mHasherCompare.in[0],
			"",
			mStorageGetCryptKeyErr.out[1],
		},
		{
			"@decryption error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetPasswordHash, mStorageGetCryptKey),
				*newMockedCipher(mCipherAdjustKey, mCipherDecryptErr),
				*newMockedHasher(mHasherCompare),
			),
			mStorageGetPasswordHash.in[0],
			mHasherCompare.in[0],
			"",
			mCipherDecryptErr.out[1],
		},
		{
			"@successful run",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetPasswordHash, mStorageGetCryptKey),
				*newMockedCipher(mCipherAdjustKey, mCipherDecrypt),
				*newMockedHasher(mHasherCompare),
			),
			mStorageGetPasswordHash.in[0],
			mHasherCompare.in[0],
			mCipherDecrypt.out[0],
			nil,
		},
	}
	test := func(t *testing.T, m SimpleManager, path, password, exp string, eErr error) {
		act, aErr := m.GetCryptKey(path, password)
		assertEqualError(t, eErr, aErr)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func TestSimpleManager_AddDataUnit(t *testing.T) {
	mCipherEncryptErr := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"value1","pair2":"value2"}`},
		out:  []any{"", errors.New("encryption error")},
	}
	mCipherEncrypt := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"value1","pair2":"value2"}`},
		out:  []any{"encrypted-pairs", nil},
	}
	mStorageAddDataUnitErr := mockedMethod{
		name: "AddDataUnit",
		in:   []any{"path", "unit-name", "encrypted-pairs"},
		out:  []any{errors.New("adding data unit error")},
	}
	mStorageAddDataUnit := mockedMethod{
		name: "AddDataUnit",
		in:   []any{"path", "unit-name", "encrypted-pairs"},
		out:  []any{nil},
	}
	dataUnits := models.DataUnit{
		Name:  "unit-name",
		Pairs: map[string]string{"pair1": "value1", "pair2": "value2"},
	}
	data := []tab.Args{
		{
			"@encryption error",
			*NewSimpleManager(
				*newMockedStorage(),
				*newMockedCipher(mCipherEncryptErr),
				*newMockedHasher(),
			),
			mStorageAddDataUnit.in[0],
			mCipherEncryptErr.in[0],
			dataUnits,
			mCipherEncryptErr.out[1],
		},
		{
			"@adding data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageAddDataUnitErr),
				*newMockedCipher(mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageAddDataUnit.in[0],
			mCipherEncryptErr.in[0],
			dataUnits,
			mStorageAddDataUnitErr.out[0],
		},
		{
			"@successful run",
			*NewSimpleManager(
				*newMockedStorage(mStorageAddDataUnit),
				*newMockedCipher(mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageAddDataUnit.in[0],
			mCipherEncryptErr.in[0],
			dataUnits,
			nil,
		},
	}
	test := func(t *testing.T, m SimpleManager, path, key string, unit models.DataUnit, eErr error) {
		aErr := m.AddDataUnit(path, key, unit)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestSimpleManager_AddDataPairs(t *testing.T) {
	mStorageGetDataUnitErr := mockedMethod{
		name: "GetDataUnit",
		in:   []any{"path", "unit-name"},
		out:  []any{"", errors.New("getting data unit error")},
	}
	mStorageGetDataUnit := mockedMethod{
		name: "GetDataUnit",
		in:   []any{"path", "unit-name"},
		out:  []any{"unit-value", nil},
	}
	mCipherDecryptErr := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "unit-value"},
		out:  []any{"", errors.New("decryption error")},
	}
	mCipherDecrypt := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "unit-value"},
		out:  []any{`{"pair1":"value1","pair2":"value2"}`, nil},
	}
	mCipherEncryptErr := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"value1","pair2":"value2","pair3":"value3","pair4":"value4"}`},
		out:  []any{"", errors.New("encryption error")},
	}
	mCipherEncrypt := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"value1","pair2":"value2","pair3":"value3","pair4":"value4"}`},
		out:  []any{"updated-unit-value", nil},
	}
	mStorageUpdateDataUnitErr := mockedMethod{
		name: "UpdateDataUnit",
		in:   []any{"path", "unit-name", "updated-unit-value"},
		out:  []any{errors.New("updating data unit error")},
	}
	mStorageUpdateDataUnit := mockedMethod{
		name: "UpdateDataUnit",
		in:   []any{"path", "unit-name", "updated-unit-value"},
		out:  []any{nil},
	}
	pairs := []models.DataPair{
		models.DataPair{"", "value"},
		models.DataPair{"pair2", "value"},
		models.DataPair{"pair3", "value3"},
		models.DataPair{"pair4", "value4"},
	}
	data := []tab.Args{
		{
			"@getting data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnitErr),
				*newMockedCipher(),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mStorageGetDataUnitErr.out[1],
		},
		{
			"@decription error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit),
				*newMockedCipher(mCipherDecryptErr),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mCipherDecryptErr.out[1],
		},
		{
			"@encryption error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit),
				*newMockedCipher(mCipherDecrypt, mCipherEncryptErr),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mCipherEncryptErr.out[1],
		},
		{
			"@updating data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit, mStorageUpdateDataUnitErr),
				*newMockedCipher(mCipherDecrypt, mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mStorageUpdateDataUnitErr.out[0],
		},
		{
			"@successful run",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit, mStorageUpdateDataUnit),
				*newMockedCipher(mCipherDecrypt, mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			errors.Join(
				fmt.Errorf("%w: %q=%q %q=%q %q=%q", ErrEmptyDataPairName, "file", mStorageGetDataUnit.in[0], "data unit", mStorageGetDataUnit.in[1], "data pair", ""),
				fmt.Errorf("%w: %q=%q %q=%q %q=%q", ErrDataPairIsAlreadyPresent, "file", mStorageGetDataUnit.in[0], "data unit", mStorageGetDataUnit.in[1], "data pair", "pair2"),
			),
		},
	}
	test := func(t *testing.T, m SimpleManager, path, key, unitName string, pairs []models.DataPair, eErr error) {
		aErr := m.AddDataPairs(path, key, unitName, pairs...)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestSimpleManager_UpdateDataPair(t *testing.T) {
	mStorageGetDataUnitErr := mockedMethod{
		name: "GetDataUnit",
		in:   []any{"path", "unit-name"},
		out:  []any{"", errors.New("getting data unit error")},
	}
	mStorageGetDataUnit := mockedMethod{
		name: "GetDataUnit",
		in:   []any{"path", "unit-name"},
		out:  []any{"unit-value", nil},
	}
	mCipherDecryptErr := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "unit-value"},
		out:  []any{"", errors.New("decryption error")},
	}
	mCipherDecrypt := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "unit-value"},
		out:  []any{`{"pair1":"value1","pair2":"value2"}`, nil},
	}
	mCipherEncryptErr := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"updated-value1","pair2":"value2"}`},
		out:  []any{"", errors.New("encryption error")},
	}
	mCipherEncrypt := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"updated-value1","pair2":"value2"}`},
		out:  []any{"updated-unit-value", nil},
	}
	mStorageUpdateDataUnitErr := mockedMethod{
		name: "UpdateDataUnit",
		in:   []any{"path", "unit-name", "updated-unit-value"},
		out:  []any{errors.New("updating data unit error")},
	}
	mStorageUpdateDataUnit := mockedMethod{
		name: "UpdateDataUnit",
		in:   []any{"path", "unit-name", "updated-unit-value"},
		out:  []any{nil},
	}
	pair := models.DataPair{"pair1", "updated-value1"}
	data := []tab.Args{
		{
			"@getting data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnitErr),
				*newMockedCipher(),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pair,
			mStorageGetDataUnitErr.out[1],
		},
		{
			"@decription error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit),
				*newMockedCipher(mCipherDecryptErr),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pair,
			mCipherDecryptErr.out[1],
		},
		{
			"@data pair not found error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit),
				*newMockedCipher(mCipherDecrypt),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			models.DataPair{"pair3", "updated-value3"},
			ErrDataPairNotFound,
		},
		{
			"@encryption error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit),
				*newMockedCipher(mCipherDecrypt, mCipherEncryptErr),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pair,
			mCipherEncryptErr.out[1],
		},
		{
			"@updating data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit, mStorageUpdateDataUnitErr),
				*newMockedCipher(mCipherDecrypt, mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pair,
			mStorageUpdateDataUnitErr.out[0],
		},
		{
			"@successful run",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit, mStorageUpdateDataUnit),
				*newMockedCipher(mCipherDecrypt, mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pair,
			nil,
		},
	}
	test := func(t *testing.T, m SimpleManager, path, key, unitName string, pair models.DataPair, eErr error) {
		aErr := m.UpdateDataPair(path, key, unitName, pair)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestSimpleManager_DeleteDataPairs(t *testing.T) {
	mStorageGetDataUnitErr := mockedMethod{
		name: "GetDataUnit",
		in:   []any{"path", "unit-name"},
		out:  []any{"", errors.New("getting data unit error")},
	}
	mStorageGetDataUnit := mockedMethod{
		name: "GetDataUnit",
		in:   []any{"path", "unit-name"},
		out:  []any{"unit-value", nil},
	}
	mCipherDecryptErr := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "unit-value"},
		out:  []any{"", errors.New("decryption error")},
	}
	mCipherDecrypt := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "unit-value"},
		out:  []any{`{"pair1":"value1","pair2":"value2"}`, nil},
	}
	mCipherEncryptErr := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"value1"}`},
		out:  []any{"", errors.New("encryption error")},
	}
	mCipherEncrypt := mockedMethod{
		name: "Encrypt",
		in:   []any{"key", `{"pair1":"value1"}`},
		out:  []any{"updated-unit-value", nil},
	}
	mStorageUpdateDataUnitErr := mockedMethod{
		name: "UpdateDataUnit",
		in:   []any{"path", "unit-name", "updated-unit-value"},
		out:  []any{errors.New("updating data unit error")},
	}
	mStorageUpdateDataUnit := mockedMethod{
		name: "UpdateDataUnit",
		in:   []any{"path", "unit-name", "updated-unit-value"},
		out:  []any{nil},
	}
	pairs := []string{"pair3", "pair2"}
	data := []tab.Args{
		{
			"@getting data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnitErr),
				*newMockedCipher(),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mStorageGetDataUnitErr.out[1],
		},
		{
			"@decription error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit),
				*newMockedCipher(mCipherDecryptErr),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mCipherDecryptErr.out[1],
		},
		{
			"@encryption error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit),
				*newMockedCipher(mCipherDecrypt, mCipherEncryptErr),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mCipherEncryptErr.out[1],
		},
		{
			"@updating data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit, mStorageUpdateDataUnitErr),
				*newMockedCipher(mCipherDecrypt, mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			mStorageUpdateDataUnitErr.out[0],
		},
		{
			"@successful run",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnit, mStorageUpdateDataUnit),
				*newMockedCipher(mCipherDecrypt, mCipherEncrypt),
				*newMockedHasher(),
			),
			mStorageGetDataUnit.in[0],
			mCipherDecrypt.in[0],
			mStorageGetDataUnit.in[1],
			pairs,
			fmt.Errorf("%w: %q=%q %q=%q %q=%q", ErrDataPairNotFound, "file", mStorageGetDataUnit.in[0], "data unit", mStorageGetDataUnit.in[1], "data pair", "pair3"),
		},
	}
	test := func(t *testing.T, m SimpleManager, path, key, unitName string, pairs []string, eErr error) {
		aErr := m.DeleteDataPairs(path, key, unitName, pairs...)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestSimpleManager_Search(t *testing.T) {
	units := map[string]string{
		"instagram": "instagram",
		"facebook":   "facebook",
		"google":     "google",
	}
	mStorageGetDataUnitsErr := mockedMethod{
		name: "GetDataUnits",
		in:   []any{"path"},
		out:  []any{nil, errors.New("getting data unit error")},
	}
	mStorageGetDataUnits := mockedMethod{
		name: "GetDataUnits",
		in:   []any{"path"},
		out:  []any{units, nil},
	}
	mCipherDecryptInstagramErr := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "instagram"},
		out:  []any{"", errors.New("decryption error")},
	}
	mCipherDecryptInstagram := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "instagram"},
		out:  []any{`{"password":"myinstagram","email":"instagram@"}`, nil},
	}
	mCipherDecryptFacebook := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "facebook"},
		out:  []any{`{"password":"myfacebook","email":"facebook@","username":"facebook"}`, nil},
	}
	mCipherDecryptGoogle := mockedMethod{
		name: "Decrypt",
		in:   []any{"key", "google"},
		out:  []any{`{"password":"mygoogle","email":"google@"}`, nil},
	}
	data := []tab.Args{
		{
			"@getting data unit error",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnitsErr),
				*newMockedCipher(),
				*newMockedHasher(),
			),
			mStorageGetDataUnits.in[0],
			mCipherDecryptInstagram.in[0],
			regexp.MustCompile(".*"),
			regexp.MustCompile(".*"),
			nil,
			mStorageGetDataUnitsErr.out[1],
		},
		{
			"@decryption error",
			*NewSimpleManager(
				*newMockedStorage(
					mockedMethod{
						name: "GetDataUnits",
						in: []any{"path"},
						out: []any{map[string]string{"instagram":"instagram"}, nil},
					},
				),
				*newMockedCipher(mCipherDecryptInstagramErr),
				*newMockedHasher(),
			),
			mStorageGetDataUnits.in[0],
			mCipherDecryptInstagram.in[0],
			regexp.MustCompile(".*"),
			regexp.MustCompile(".*"),
			nil,
			mCipherDecryptInstagramErr.out[1],
		},
		{
			"@successful run: match everything",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnits),
				*newMockedCipher(mCipherDecryptInstagram, mCipherDecryptFacebook, mCipherDecryptGoogle),
				*newMockedHasher(),
			),
			mStorageGetDataUnits.in[0],
			mCipherDecryptInstagram.in[0],
			regexp.MustCompile(".*"),
			regexp.MustCompile(".*"),
			[]models.DataUnit{
				models.DataUnit{"instagram", map[string]string{
					"password": "myinstagram",
					"email": "instagram@",
				}},
				models.DataUnit{"facebook", map[string]string{
					"password": "myfacebook",
					"email": "facebook@",
					"username": "facebook",
				}},
				models.DataUnit{"google", map[string]string{
					"password": "mygoogle",
					"email": "google@",
				}},
			},
			nil,
		},
		{
			"@successful run",
			*NewSimpleManager(
				*newMockedStorage(mStorageGetDataUnits),
				*newMockedCipher(mCipherDecryptInstagram, mCipherDecryptFacebook, mCipherDecryptGoogle),
				*newMockedHasher(),
			),
			mStorageGetDataUnits.in[0],
			mCipherDecryptInstagram.in[0],
			regexp.MustCompile("oo"),
			regexp.MustCompile("email"),
			[]models.DataUnit{
				models.DataUnit{"facebook", map[string]string{"email": "facebook@"}},
				models.DataUnit{"google", map[string]string{"email": "google@"}},
			},
			nil,
		},
	}
	test := func(t *testing.T, m SimpleManager, path, key string, unitRegexp, pairRegexp *regexp.Regexp, exp []models.DataUnit, eErr error) {
		act, aErr := m.Search(path, key, unitRegexp, pairRegexp)
		assertEqualError(t, eErr, aErr)
		assert.ElementsMatch(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func newMockedStorage(methods ...mockedMethod) *mockedStorage {
	m := &mockedStorage{}
	fillMock(&m.Mock, methods...)
	return m
}

type mockedStorage struct {
	mock.Mock
}

func (m mockedStorage) CreateStorageFile(path, passHash, cryptKey string) error {
	return m.Called(path, passHash, cryptKey).Error(0)
}

func (m mockedStorage) GetPasswordHash(path string) (string, error) {
	args := m.Called(path)
	return args.String(0), args.Error(1)
}

func (m mockedStorage) GetCryptKey(path string) (string, error) {
	args := m.Called(path)
	return args.String(0), args.Error(1)
}

func (m mockedStorage) GetDataUnit(path, name string) (string, error) {
	args := m.Called(path, name)
	return args.String(0), args.Error(1)
}

func (m mockedStorage) GetDataUnits(path string) (map[string]string, error) {
	args := m.Called(path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m mockedStorage) AddDataUnit(path, name, value string) error {
	return m.Called(path, name, value).Error(0)
}

func (m mockedStorage) UpdateDataUnit(path, name, value string) error {
	return m.Called(path, name, value).Error(0)
}

func (m mockedStorage) DeleteDataUnit(path, name string) error {
	return m.Called(path, name).Error(0)
}

func (m mockedStorage) DeleteDataUnits(path string, names ...string) error {
	return m.Called(path, names).Error(0)
}

func newMockedCipher(methods ...mockedMethod) *mockedCipher {
	m := &mockedCipher{}
	fillMock(&m.Mock, methods...)
	return m
}

type mockedCipher struct {
	mock.Mock
}

func (m mockedCipher) GenerateKey() string {
	return m.Called().String(0)
}

func (m mockedCipher) AdjustKey(key string) string {
	return m.Called(key).String(0)
}

func (m mockedCipher) Encrypt(key, plaintext string) (string, error) {
	args := m.Called(key, plaintext)
	return args.String(0), args.Error(1)
}

func (m mockedCipher) Decrypt(key, ciphertext string) (string, error) {
	args := m.Called(key, ciphertext)
	return args.String(0), args.Error(1)
}

func newMockedHasher(methods ...mockedMethod) *mockedHasher {
	m := &mockedHasher{}
	fillMock(&m.Mock, methods...)
	return m
}

type mockedHasher struct {
	mock.Mock
}

func (m mockedHasher) Hash(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m mockedHasher) Compare(password, hash string) error {
	return m.Called(password, hash).Error(0)
}

func assertEqualError(t *testing.T, eErr, aErr error) {
	if eErr == nil {
		assert.NoError(t, aErr)
		return
	}
	if assert.Error(t, aErr) && aErr.Error() != eErr.Error() {
		assert.ErrorIs(t, aErr, eErr)
	}
}
