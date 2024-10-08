package services_test

import (
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	. "github.com/branow/simpass/services"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hasher Hasher = BCryptHasher{}

func TestBCryptHasher(t *testing.T) {
	n := 5
	for i := 0; i < n; i++ {
		pwb := make([]byte, 8)
		rand.Reader.Read(pwb)
		pw := string(pwb)
		for j := 0; j < n; j++ {
			hash, _ := hasher.HashHex(pw)
			aErr := hasher.CompareHex(pw, hash)
			require.NoError(t, aErr)
		}
	}
}

func TestBCryptHasher_HashHex(t *testing.T) {
	pwb := make([]byte, 8)
	rand.Reader.Read(pwb)
	pw := string(pwb)
	size := 25
	hash := make([]string, 0, size)
	for i := 0; i < size; i++ {
		h, _ := hasher.HashHex(pw)
		require.Conditionf(t,
			func() bool { return !slices.Contains(hash[0:i], pw) },
			`too identical hash: "%s"`, h)

		hash = append(hash, h)
	}
}

func TestBCryptHasher_CompareHex(t *testing.T) {
	args := []tab.Args{
		{
			"@match", "12345678",
			"243261243132247731786b735176536457726d5a6453793750696a6b65734964566f6d76363531624a70445949665762574a4d4250362e3475684643",
			nil,
		},
		{
			"@not match", "12345678",
			"243261243132247731786b735176536457726d5a6453793750696a6b65734964566f6d76363531624a70445949665762574a4d4250362e3475684644",
			PasswordHashMismatchErr{},
		},
		{
			"@not match", "12345678",
			"2432612j3132247731786b735176536457726d5a6453793750696a6b65734964566f6d76363531624a70445949665762574a4d4250362e3475684643",
			errors.New("encoding/hex: invalid byte: U+006A 'j'"),
		},
	}
	test := func(t *testing.T, password, hash string, eErr error) {
		aErr := hasher.CompareHex(password, hash)
		if eErr != nil {
			require.Error(t, aErr)
			assert.EqualError(t, aErr, eErr.Error())
		} else {
			assert.NoError(t, aErr)
		}
	}
	tab.RunWithArgs(t, args, test)
}
