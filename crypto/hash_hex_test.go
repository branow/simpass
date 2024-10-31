package crypto_test

import (
	"errors"
	"testing"

	. "github.com/branow/simpass/crypto"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHasherHex_Hash(t *testing.T) {
	args := []tab.Args{
		{
			"@successful case",
			newMockedHasher(
				mockedMethod{
					name: "Hash",
					in:   []any{[]byte("password")},
					out:  []any{[]byte("hash"), nil},
				},
			),
			"password",
			"68617368",
		},
	}
	test := func(t *testing.T, h Hasher, password, exp string) {
		act, _ := HasherHex{Hasher: h}.Hash(password)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, args, test)
}

func TestHasherHex_Compare(t *testing.T) {
	args := []tab.Args{
		{
			"@hex decoding error",
			newMockedHasher(),
			"password",
			"g1626364",
			errors.New("encoding/hex: invalid byte: U+0067 'g'"),
		},
		{
			"@match",
			newMockedHasher(
				mockedMethod{
					name: "Compare",
					in:   []any{[]byte("password"), []byte("hash")},
					out:  []any{nil},
				},
			),
			"password",
			"68617368",
			nil,
		},
	}
	test := func(t *testing.T, h Hasher, pw, hash string, exp error) {
		act := HasherHex{Hasher: h}.Compare(pw, hash)
		if exp != nil {
			assert.EqualError(t, exp, act.Error())
		} else {
			assert.NoError(t, act)
		}
	}
	tab.RunWithArgs(t, args, test)
}

func newMockedHasher(methods ...mockedMethod) *mockedHasher {
	m := &mockedHasher{}
	fillMock(&(m.Mock), methods...)
	return m
}

type mockedHasher struct {
	mock.Mock
}

func (m mockedHasher) Hash(password []byte) ([]byte, error) {
	r := m.Called(password)
	return r.Get(0).([]byte), r.Error(1)
}

func (m mockedHasher) Compare(password, hash []byte) error {
	return m.Called(password, hash).Error(0)
}
