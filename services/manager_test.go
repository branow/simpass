package services_test

import (
	"errors"
	"regexp"
	"testing"

	"github.com/branow/simpass/models"
	. "github.com/branow/simpass/services"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestManagerImpl_CreateStorageFile(t *testing.T) {
	data := []tab.Args{
		{
			"@encrypt hex error",
			NewManagerImpl(
				*NewMockedStorage(),
				*NewMockedCipher(
					*NewMockedMethod(
						"AdjustKeyHex",
						[]any{"password"},
						[]any{"adjust-password"},
					),
					*NewMockedMethod(
						"GenerateKeyHex",
						[]any{},
						[]any{"crypt-key"},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"adjust-password", "crypt-key"},
						[]any{"", errors.New("encrypt error")},
					),
				),
				*NewMockedHasher(),
			),
			"",
			"password",
			errors.New("encrypt error"),
		},
		{
			"@hash hex error",
			NewManagerImpl(
				*NewMockedStorage(),
				*NewMockedCipher(
					*NewMockedMethod(
						"AdjustKeyHex",
						[]any{"password"},
						[]any{"adjust-password"},
					),
					*NewMockedMethod(
						"GenerateKeyHex",
						[]any{},
						[]any{"crypt-key"},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"adjust-password", "crypt-key"},
						[]any{"encrypted-key", nil},
					),
				),
				*NewMockedHasher(
					*NewMockedMethod(
						"HashHex",
						[]any{"password"},
						[]any{"", errors.New("hash error")},
					),
				),
			),
			"",
			"password",
			errors.New("hash error"),
		},
		{
			"@hash create storage filer",
			NewManagerImpl(
				*NewMockedStorage(
					*NewMockedMethod(
						"CreateStorageFile",
						[]any{"path", "hashed-password", "encrypted-key"},
						[]any{errors.New("create file error")},
					),
				),
				*NewMockedCipher(
					*NewMockedMethod(
						"AdjustKeyHex",
						[]any{"password"},
						[]any{"adjust-password"},
					),
					*NewMockedMethod(
						"GenerateKeyHex",
						[]any{},
						[]any{"crypt-key"},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"adjust-password", "crypt-key"},
						[]any{"encrypted-key", nil},
					),
				),
				*NewMockedHasher(
					*NewMockedMethod(
						"HashHex",
						[]any{"password"},
						[]any{"hashed-password", nil},
					),
				),
			),
			"path",
			"password",
			errors.New("create file error"),
		},
		{
			"@normal run",
			NewManagerImpl(
				*NewMockedStorage(
					*NewMockedMethod(
						"CreateStorageFile",
						[]any{"path", "hashed-password", "encrypted-key"},
						[]any{nil},
					),
				),
				*NewMockedCipher(
					*NewMockedMethod(
						"AdjustKeyHex",
						[]any{"password"},
						[]any{"adjust-password"},
					),
					*NewMockedMethod(
						"GenerateKeyHex",
						[]any{},
						[]any{"crypt-key"},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"adjust-password", "crypt-key"},
						[]any{"encrypted-key", nil},
					),
				),
				*NewMockedHasher(
					*NewMockedMethod(
						"HashHex",
						[]any{"password"},
						[]any{"hashed-password", nil},
					),
				),
			),
			"path",
			"password",
			nil,
		},
	}
	test := func(t *testing.T, manager models.Manager, path, password string, eErr error) {
		aErr := manager.CreateStorageFile(path, password)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestManagerImpl_GetCryptKey(t *testing.T) {
	data := []tab.Args{
		{
			"@wrong password err",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetPasswordHash",
						[]any{"path"},
						[]any{"password-hash", nil},
					),
				),
				NewMockedCipher(),
				NewMockedHasher(
					*NewMockedMethod(
						"CompareHex",
						[]any{"password", "password-hash"},
						[]any{PasswordHashMismatchErr{}},
					),
				),
			),
			"path",
			"password",
			"",
			models.WrongPasswordErr{Path: "path"},
		},
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetPasswordHash",
						[]any{"path"},
						[]any{"password-hash", nil},
					),
					*NewMockedMethod(
						"GetCryptKey",
						[]any{"path"},
						[]any{"encrypted-key", nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"AdjustKeyHex",
						[]any{"password"},
						[]any{"adjust-password"},
					),
					*NewMockedMethod(
						"DecryptHex",
						[]any{"adjust-password", "encrypted-key"},
						[]any{"crypt-key", nil},
					),
				),
				NewMockedHasher(
					*NewMockedMethod(
						"CompareHex",
						[]any{"password", "password-hash"},
						[]any{nil},
					),
				),
			),
			"path",
			"password",
			"crypt-key",
			nil,
		},
	}
	test := func(t *testing.T, manager models.Manager, path, password, exp string, eErr error) {
		act, aErr := manager.GetCryptKey(path, password)
		assertEqualError(t, eErr, aErr)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func TestManagerImpl_AddDataUnit(t *testing.T) {
	data := []tab.Args{
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(),
				NewMockedCipher(),
				NewMockedHasher(),
			),
			"path",
			"",
			models.DataUnit{Name: "", Pairs: map[string]string{"p1": "v1"}},
			models.EmptyDataUnitNameErr{Path: "path", Pairs: map[string]string{"p1": "v1"}},
		},
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"AddDataUnit",
						[]any{"path", "unit-name", "encrypted-pairs"},
						[]any{nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"EncryptHex",
						[]any{"key", `{"pair1":"value","pair2":"value"}`},
						[]any{"encrypted-pairs", nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			models.DataUnit{
				Name:  "unit-name",
				Pairs: map[string]string{"pair1": "value", "pair2": "value"},
			},
			nil,
		},
	}
	test := func(t *testing.T, manager models.Manager, path, key string,
		unit models.DataUnit, eErr error) {
		aErr := manager.AddDataUnit(path, key, unit)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestManagerImpl_DeleteDataUnits(t *testing.T) {
	data := []tab.Args{
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"DeleteDataUnits",
						[]any{"path", []string{"name1", "name2"}},
						[]any{nil},
					),
				),
				NewMockedCipher(),
				NewMockedHasher(),
			),
			"path",
			[]string{"name1", "name2"},
			nil,
		},
	}
	test := func(t *testing.T, manager models.Manager, path string,
		names []string, eErr error) {
		aErr := manager.DeleteDataUnits(path, names...)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestManagerImpl_AddDataPairs(t *testing.T) {
	data := []tab.Args{
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetDataUnit",
						[]any{"path", "unit-name"},
						[]any{"encrypted-pairs-old", nil},
					),
					*NewMockedMethod(
						"UpdateDataUnit",
						[]any{"path", "unit-name", "encrypted-pairs-new"},
						[]any{nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs-old"},
						[]any{`{"pair1":"1","pair2":"2"}`, nil},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"key", `{"pair1":"1","pair2":"2","pair3":"3","pair4":"4"}`},
						[]any{"encrypted-pairs-new", nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			"unit-name",
			[]models.DataPair{{Name: "pair3", Value: "3"}, {Name: "pair4", Value: "4"}},
			nil,
		},
		{
			"@normal run with pair errs",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetDataUnit",
						[]any{"path", "unit-name"},
						[]any{"unit-value", nil},
					),
					*NewMockedMethod(
						"UpdateDataUnit",
						[]any{"path", "unit-name", "encrypted-pairs"},
						[]any{nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "unit-value"},
						[]any{`{"p1":"1","p2":"2","p3":"3"}`, nil},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"key", `{"p1":"1","p2":"2","p3":"3","p4":"4"}`},
						[]any{"encrypted-pairs", nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			"unit-name",
			[]models.DataPair{{Name: "p3", Value: "3"}, {Name: "p4", Value: "4"}, {Name: "", Value: "5"}},
			errors.Join(
				models.DataPairAlreadyExistsErr{Path: "path", Unit: "unit-name", Name: "p3"},
				models.EmptyDataPairNameErr{Path: "path", Value: "5"},
			),
		},
	}
	test := func(t *testing.T, manager models.Manager, path, key, unitName string,
		pairs []models.DataPair, eErr error) {
		aErr := manager.AddDataPairs(path, key, unitName, pairs...)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestManagerImpl_UpdateDataPair(t *testing.T) {
	data := []tab.Args{
		{
			"@pair does not exist err",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetDataUnit",
						[]any{"path", "unit-name"},
						[]any{"encrypted-pairs", nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs"},
						[]any{`{"p1":"v1","p2":"v2"}`, nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			"unit-name",
			models.DataPair{Name: "p3", Value: "v3"},
			models.DataPairDoesNotExistErr{Path: "path", Unit: "unit-name", Name: "p3"},
		},
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetDataUnit",
						[]any{"path", "unit-name"},
						[]any{"encrypted-pairs-old", nil},
					),
					*NewMockedMethod(
						"UpdateDataUnit",
						[]any{"path", "unit-name", "encrypted-pairs-new"},
						[]any{nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs-old"},
						[]any{`{"p1":"v1","p2":"v2old"}`, nil},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"key", `{"p1":"v1","p2":"v2new"}`},
						[]any{"encrypted-pairs-new", nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			"unit-name",
			models.DataPair{Name: "p2", Value: "v2new"},
			nil,
		},
	}
	test := func(t *testing.T, manager models.Manager, path, key,
		unitName string, pair models.DataPair, eErr error) {
		aErr := manager.UpdateDataPair(path, key, unitName, pair)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestManagerImpl_DeleteDataPairs(t *testing.T) {
	data := []tab.Args{
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetDataUnit",
						[]any{"path", "unit-name"},
						[]any{"encrypted-pairs-old", nil},
					),
					*NewMockedMethod(
						"UpdateDataUnit",
						[]any{"path", "unit-name", "encrypted-pairs-new"},
						[]any{nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs-old"},
						[]any{`{"p1":"v1","p2":"v2","p3":"v3"}`, nil},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"key", `{"p2":"v2"}`},
						[]any{"encrypted-pairs-new", nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			"unit-name",
			[]string{"p1", "p3"},
			nil,
		},
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetDataUnit",
						[]any{"path", "unit-name"},
						[]any{"encrypted-pairs-old", nil},
					),
					*NewMockedMethod(
						"UpdateDataUnit",
						[]any{"path", "unit-name", "encrypted-pairs-new"},
						[]any{nil},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs-old"},
						[]any{`{"p1":"v1","p2":"v2","p3":"v3"}`, nil},
					),
					*NewMockedMethod(
						"EncryptHex",
						[]any{"key", `{"p2":"v2","p3":"v3"}`},
						[]any{"encrypted-pairs-new", nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			"unit-name",
			[]string{"p1", "p4", "p5"},
			errors.Join(
				models.DataPairDoesNotExistErr{Path: "path", Unit: "unit-name", Name: "p4"},
				models.DataPairDoesNotExistErr{Path: "path", Unit: "unit-name", Name: "p5"},
			),
		},
	}
	test := func(t *testing.T, manager models.Manager, path, key,
		unitName string, pairs []string, eErr error) {
		aErr := manager.DeleteDataPairs(path, key, unitName, pairs...)
		assertEqualError(t, eErr, aErr)
	}
	tab.RunWithArgs(t, data, test)
}

func TestManagerImpl_Search(t *testing.T) {
	data := []tab.Args{
		{
			"@normal run",
			NewManagerImpl(
				NewMockedStorage(
					*NewMockedMethod(
						"GetDataUnits",
						[]any{"path"},
						[]any{
							map[string]string{
								"instagram": "encrypted-pairs-1",
								"facebook":  "encrypted-pairs-2",
								"google":    "encrypted-pairs-3",
								"email":     "encrypted-pairs-4",
								"youtube":   "encrypted-pairs-5",
							},
							nil,
						},
					),
				),
				NewMockedCipher(
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs-2"},
						[]any{`{"password":"12345678","email":"temp@gm.com"}`, nil},
					),
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs-3"},
						[]any{`{"key":"87654321","number":"+38084651648"}`, nil},
					),
					*NewMockedMethod(
						"DecryptHex",
						[]any{"key", "encrypted-pairs-5"},
						[]any{`{"email":"temp@gm.com"}`, nil},
					),
				),
				NewMockedHasher(),
			),
			"path",
			"key",
			regexp.MustCompile("oo|you"),
			regexp.MustCompile("password|email"),
			[]models.DataUnit{
				{
					Name:  "facebook",
					Pairs: map[string]string{"password": "12345678", "email": "temp@gm.com"},
				},
				{
					Name:  "google",
					Pairs: map[string]string{},
				},
				{
					Name:  "youtube",
					Pairs: map[string]string{"email": "temp@gm.com"},
				},
			},
			nil,
		},
	}
	test := func(t *testing.T, manager models.Manager, path, key string,
		unitRegexp, pairRegexp *regexp.Regexp, exp []models.DataUnit, eErr error) {
		act, aErr := manager.Search(path, key, unitRegexp, pairRegexp)
		assertEqualError(t, eErr, aErr)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, data, test)
}

func NewMockedStorage(methods ...MockedMethod) *MockedStorage {
	m := &MockedStorage{}
	FillMock(&m.Mock, methods...)
	return m
}

type MockedStorage struct {
	mock.Mock
}

func (m MockedStorage) CreateStorageFile(path, passHash, cryptKey string) error {
	return m.Called(path, passHash, cryptKey).Error(0)
}

func (m MockedStorage) GetPasswordHash(path string) (string, error) {
	args := m.Called(path)
	return args.String(0), args.Error(1)
}

func (m MockedStorage) GetCryptKey(path string) (string, error) {
	args := m.Called(path)
	return args.String(0), args.Error(1)
}

func (m MockedStorage) GetDataUnit(path, name string) (string, error) {
	args := m.Called(path, name)
	return args.String(0), args.Error(1)
}

func (m MockedStorage) GetDataUnits(path string) (map[string]string, error) {
	args := m.Called(path)
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m MockedStorage) AddDataUnit(path, name, value string) error {
	return m.Called(path, name, value).Error(0)
}

func (m MockedStorage) UpdateDataUnit(path, name, value string) error {
	return m.Called(path, name, value).Error(0)
}

func (m MockedStorage) DeleteDataUnit(path, name string) error {
	return m.Called(path, name).Error(0)
}

func (m MockedStorage) DeleteDataUnits(path string, names ...string) error {
	return m.Called(path, names).Error(0)
}

func NewMockedCipher(methods ...MockedMethod) *MockedCipher {
	m := &MockedCipher{}
	FillMock(&m.Mock, methods...)
	return m
}

type MockedCipher struct {
	mock.Mock
}

func (m MockedCipher) GenerateKeyHex() string {
	return m.Called().String(0)
}

func (m MockedCipher) GenerateKey() []byte {
	return m.Called().Get(0).([]byte)
}

func (m MockedCipher) AdjustKeyHex(key string) string {
	return m.Called(key).String(0)
}

func (m MockedCipher) AdjustKey(key []byte) []byte {
	return m.Called(key).Get(0).([]byte)
}

func (m MockedCipher) EncryptHex(key, plaintext string) (string, error) {
	args := m.Called(key, plaintext)
	return args.String(0), args.Error(1)
}

func (m MockedCipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	args := m.Called(key, plaintext)
	return args.Get(0).([]byte), args.Error(1)
}

func (m MockedCipher) DecryptHex(key, ciphertext string) (string, error) {
	args := m.Called(key, ciphertext)
	return args.String(0), args.Error(1)
}

func (m MockedCipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	args := m.Called(key, ciphertext)
	return args.Get(0).([]byte), args.Error(1)
}

func NewMockedHasher(methods ...MockedMethod) *MockedHasher {
	m := &MockedHasher{}
	FillMock(&m.Mock, methods...)
	return m
}

type MockedHasher struct {
	mock.Mock
}

func (m MockedHasher) HashHex(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m MockedHasher) Hash(password []byte) ([]byte, error) {
	args := m.Called(password)
	return args.Get(0).([]byte), args.Error(1)
}

func (m MockedHasher) CompareHex(password, hash string) error {
	return m.Called(password, hash).Error(0)
}

func (m MockedHasher) Compare(password, hash []byte) error {
	return m.Called(password, hash).Error(0)
}

func FillMock(m *mock.Mock, methods ...MockedMethod) {
	for _, method := range methods {
		m.On(method.Name, method.In...).Return(method.Out...)
	}
}

func NewMockedMethod(name string, in []any, out []any) *MockedMethod {
	return &MockedMethod{Name: name, In: in, Out: out}
}

type MockedMethod struct {
	Name string
	In   []any
	Out  []any
}

func assertEqualError(t *testing.T, eErr, aErr error) {
	if eErr == nil {
		assert.NoError(t, aErr)
		return
	}
	assert.Error(t, aErr)
	assert.EqualError(t, aErr, eErr.Error())
}
