package crypto_test

import (
	"errors"
	"testing"

	. "github.com/branow/simpass/crypto"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCipherHex_GenerateKey(t *testing.T) {
	args := []tab.Args{
		{
			"@success",
			newMockedCipher(
				mockedMethod{
					"GenerateKey",
					[]any{},
					[]any{[]byte("abc")},
				},
			),
			"616263",
		},
	}
	test := func(t *testing.T, c Cipher, exp string) {
		act := CipherHex{Cipher: c}.GenerateKey()
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, args, test)
}

func TestCipherHex_AdjustKey(t *testing.T) {
	args := []tab.Args{
		{
			"@success",
			newMockedCipher(
				mockedMethod{
					"AdjustKey",
					[]any{[]byte("abc")},
					[]any{[]byte("abcd")},
				},
			),
			"abc",
			"61626364",
		},
	}
	test := func(t *testing.T, c Cipher, key, exp string) {
		act := CipherHex{Cipher: c}.AdjustKey(key)
		assert.Equal(t, exp, act)
	}
	tab.RunWithArgs(t, args, test)
}

func TestCipherHex_Encrypt(t *testing.T) {
	args := []tab.Args{
		{
			"@hex decoding error",
			newMockedCipher(),
			"g1626364",
			"",
			"",
			errors.New("encoding/hex: invalid byte: U+0067 'g'"),
		},
		{
			"@encryption error",
			newMockedCipher(
				mockedMethod{
					"Encrypt",
					[]any{[]byte("abcd"), []byte("plain message")},
					[]any{[]byte{}, errors.New("ecryption error")},
				},
			),
			"61626364",
			"plain message",
			"",
			errors.New("ecryption error"),
		},
		{
			"@success",
			newMockedCipher(
				mockedMethod{
					"Encrypt",
					[]any{[]byte("abcd"), []byte("plain message")},
					[]any{[]byte("cipher message"), nil},
				},
			),
			"61626364",
			"plain message",
			"636970686572206d657373616765",
			nil,
		},
	}
	test := func(t *testing.T, c Cipher, key, plaintext, exp string, eErr error) {
		act, aErr := CipherHex{Cipher: c}.Encrypt(key, plaintext)
		assert.Equal(t, exp, act)
		if eErr != nil {
			assert.EqualError(t, aErr, eErr.Error())
		} else {
			assert.NoError(t, aErr)
		}
	}
	tab.RunWithArgs(t, args, test)
}

func TestCipherHex_Decrypt(t *testing.T) {
	args := []tab.Args{
		{
			"@two hex decoding error",
			newMockedCipher(),
			"g1626364",
			"dha434ab",
			"",
			errors.New("encoding/hex: invalid byte: U+0067 'g'\nencoding/hex: invalid byte: U+0068 'h'"),
		},
		{
			"@decryption error",
			newMockedCipher(
				mockedMethod{
					"Decrypt",
					[]any{[]byte("abcd"), []byte("cipher message")},
					[]any{[]byte{}, errors.New("decryption error")},
				},
			),
			"61626364",
			"636970686572206d657373616765",
			"",
			errors.New("decryption error"),
		},
		{
			"@success",
			newMockedCipher(
				mockedMethod{
					"Decrypt",
					[]any{[]byte("abcd"), []byte("cipher message")},
					[]any{[]byte("plain message"), nil},
				},
			),
			"61626364",
			"636970686572206d657373616765",
			"plain message",
			nil,
		},
	}
	test := func(t *testing.T, c Cipher, key, ciphertext, exp string, eErr error) {
		act, aErr := CipherHex{Cipher: c}.Decrypt(key, ciphertext)
		assert.Equal(t, exp, act)
		if eErr != nil {
			assert.EqualError(t, aErr, eErr.Error())
		} else {
			assert.NoError(t, aErr)
		}
	}
	tab.RunWithArgs(t, args, test)
}

func newMockedCipher(methods ...mockedMethod) *mockedCipher {
	m := &mockedCipher{}
	fillMock(&(m.Mock), methods...)
	return m
}

type mockedCipher struct {
	mock.Mock
}

func (m mockedCipher) GenerateKey() []byte {
	return m.Called().Get(0).([]byte)
}

func (m mockedCipher) AdjustKey(key []byte) []byte {
	return m.Called(key).Get(0).([]byte)
}

func (m mockedCipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	r := m.Called(key, plaintext)
	return r.Get(0).([]byte), r.Error(1)
}

func (m mockedCipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	r := m.Called(key, ciphertext)
	return r.Get(0).([]byte), r.Error(1)
}
