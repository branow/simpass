package storage_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/branow/simpass/models"
	. "github.com/branow/simpass/storage"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
)

var storage = NewJsonStorage()

func TestJsonStorage_CreateStorageFile(t *testing.T) {
	data := []tab.Args{
		{
			"@file already exists error",
			createFile(t, "./testdata/csf_1.json"),
			"", "", "",
			models.ErrFileAlreadyExists,
		},
		{
			"@successful creation",
			"./testdata/csf_2.json",
			"some-password-hash",
			"some-crypt-key",
			"./testdata/empty.json",
			nil,
		},
	}
	test := func(t *testing.T, path, passHash, cryptKey, ePath string, eErr error) {
		t.Cleanup(func() {
			err := os.Remove(path)
			if err != nil {
				fmt.Println("REMOVE FILE ERROR", err)
			}
		})

		aErr := storage.CreateStorageFile(path, passHash, cryptKey)
		assert.ErrorIs(t, aErr, eErr)

		if aErr == nil && eErr == nil {
			assertEqualJsonFile(t, ePath, path)
		}
	}
	tab.RunWithArgs(t, data, test)
}

func TestJsonStorage_GetPasswordHash(t *testing.T) {
	data := []tab.Args{
		{
			"@file does not exist",
			"./testdata/not_exist",
			"",
			models.ErrFileDoesNotExist,
		},
		{
			"@successful read",
			"./testdata/data.json",
			"some-password-hash",
			nil,
		},
	}
	test := func(t *testing.T, path, exp string, eErr error) {
		act, aErr := storage.GetPasswordHash(path)
		assert.ErrorIs(t, aErr, eErr)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func TestJsonStorage_GetCryptKey(t *testing.T) {
	data := []tab.Args{
		{
			"@file does not exist",
			"./testdata/not_exist",
			"",
			models.ErrFileDoesNotExist,
		},
		{
			"@successful read",
			"./testdata/data.json",
			"some-crypt-key",
			nil,
		},
	}
	test := func(t *testing.T, path, exp string, eErr error) {
		act, aErr := storage.GetCryptKey(path)
		assert.ErrorIs(t, aErr, eErr)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func TestJsonStorage_GetDataUnits(t *testing.T) {
	data := []tab.Args{
		{
			"@file does not exist",
			"./testdata/not_exist",
			nil,
			models.ErrFileDoesNotExist,
		},
		{
			"@no data untis err",
			"./testdata/empty.json",
			nil,
			models.ErrNoDataUnits,
		},
		{
			"@successful get",
			"./testdata/data.json",
			map[string]string{
				"unit1": "unit1_value",
				"unit2": "unit2_value",
				"unit3": "unit3_value",
			},
			nil,
		},
	}
	test := func(t *testing.T, path string, exp map[string]string, eErr error) {
		act, aErr := storage.GetDataUnits(path)
		assert.ErrorIs(t, aErr, eErr)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func TestJsonStorage_GetDataUnit(t *testing.T) {
	data := []tab.Args{
		{
			"@file does not exist error",
			"./testdata/not_exist",
			"", "",
			models.ErrFileDoesNotExist,
		},
		{
			"@no data units error",
			"./testdata/empty.json",
			"unit",
			"",
			models.ErrNoDataUnits,
		},
		{
			"@data unit not found error",
			"./testdata/data.json",
			"unit",
			"",
			models.ErrDataUnitNotFound,
		},
		{
			"@successful get",
			"./testdata/data.json",
			"unit1",
			"unit1_value",
			nil,
		},
	}
	test := func(t *testing.T, path, name, exp string, eErr error) {
		act, aErr := storage.GetDataUnit(path, name)
		assert.ErrorIs(t, aErr, eErr)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func TestJsonStorage_AddDataUnit(t *testing.T) {
	data := []tab.Args{
		{
			"@unit exists",
			"./testdata/data.json",
			"unit1",
			"unit1_value",
			"",
			models.ErrDataUnitIsAlreadyPresent,
		},
		{
			"@add unit to empty",
			"./testdata/empty.json",
			"unit",
			"unit_value",
			"./testdata/adu-2e.json",
			nil,
		},
		{
			"@add unit",
			"./testdata/data.json",
			"unit",
			"unit_value",
			"./testdata/adu-3e.json",
			nil,
		},
	}
	i := 0
	test := func(t *testing.T, path, name, value, ePath string, eErr error) {
		i++
		path = copy(t, path, fmt.Sprintf("./testdata/adu-%da.json", i))
		t.Cleanup(func() {
			os.Remove(path)
		})
		aErr := storage.AddDataUnit(path, name, value)
		assert.ErrorIs(t, aErr, eErr)

		if aErr == nil && eErr == nil {
			assertEqualJsonFile(t, ePath, path)
		}
	}
	tab.RunWithArgs(t, data, test)
}

func TestJsonStorage_UpdateDataUnit(t *testing.T) {
	data := []tab.Args{
		{
			"@unit does not exist",
			"./testdata/data.json",
			"unit",
			"unit1_value",
			"",
			models.ErrDataUnitNotFound,
		},
		{
			"@update unit",
			"./testdata/data.json",
			"unit1",
			"unit_value",
			"./testdata/udu-2e.json",
			nil,
		},
	}
	i := 0
	test := func(t *testing.T, path, name, value, ePath string, eErr error) {
		i++
		path = copy(t, path, fmt.Sprintf("./testdata/udu-%da.json", i))
		t.Cleanup(func() {
			os.Remove(path)
		})
		aErr := storage.UpdateDataUnit(path, name, value)
		assert.ErrorIs(t, aErr, eErr)

		if aErr == nil && eErr == nil {
			assertEqualJsonFile(t, ePath, path)
		}
	}
	tab.RunWithArgs(t, data, test)
}

func TestJsonStorage_DeleteDataUnits(t *testing.T) {
	data := []tab.Args{
		{
			"@units not found errors",
			"./testdata/data.json",
			[]string{"unit1", "unit4", "unit5"},
			"./testdata/ddu-1e.json",
			[]error{models.ErrDataUnitNotFound, models.ErrDataUnitNotFound},
		},
		{
			"@completely successful delete",
			"./testdata/data.json",
			[]string{"unit2"},
			"./testdata/ddu-2e.json",
			nil,
		},
	}
	i := 0
	test := func(t *testing.T, path string, names []string, ePath string, eErrs []error) {
		i++
		path = copy(t, path, fmt.Sprintf("./testdata/ddu-%da.json", i))
		t.Cleanup(func() {
			os.Remove(path)
		})

		aErr := storage.DeleteDataUnits(path, names...)
		assertErrorsIs(t, eErrs, aErr)
		assertEqualJsonFile(t, ePath, path)
	}
	tab.RunWithArgs(t, data, test)
}

func copy(t *testing.T, path, copyPath string) string {
	file, err := os.Create(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, err = file.Write([]byte(readFile(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return copyPath
}

func createFile(t *testing.T, path string) string {
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	return path
}

func readFile(t *testing.T, path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertEqualError(t *testing.T, aErr, eErr error) {
	if eErr == nil {
		assert.NoError(t, aErr)
		return
	}
	assert.Error(t, aErr)
	assert.EqualError(t, aErr, eErr.Error())
}

func assertErrorsIs(t *testing.T, eErrs []error, aErr error) {
	if eErrs == nil {
		assert.NoError(t, aErr)
		return
	}
	aErrs := aErr.(interface{ Unwrap() []error }).Unwrap()
	assert.Equalf(t, len(eErrs), len(aErrs), "expected: %v, actual: %v", eErrs, aErrs)
	for _, eErr := range eErrs {
		assert.ErrorIs(t, aErr, eErr)
	}
}

func assertEqualJsonFile(t *testing.T, ePath, aPath string) {
	act := readFile(t, aPath)
	exp := readFile(t, ePath)
	exp = strings.ReplaceAll(exp, "\r", "")
	exp = strings.ReplaceAll(exp, "  ", "\t")
	assert.Equal(t, exp, act)
}
