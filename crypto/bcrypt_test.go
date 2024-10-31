package crypto_test

import (
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	. "github.com/branow/simpass/crypto"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hasher = BCryptHasher{}

func TestBCryptHasher(t *testing.T) {
	n := 10
	for i := 0; i < n; i++ {
		pw := make([]byte, 8)
		rand.Reader.Read(pw)
		hash, _ := hasher.Hash(pw)
		aErr := hasher.Compare(pw, hash)
		require.NoError(t, aErr)
	}
}

func TestBCryptHasher_Hash(t *testing.T) {
	password := make([]byte, 8)
	rand.Read(password)
	size := 10
	hash := make([]string, 0, size)
	for i := 0; i < size; i++ {
		h, _ := hasher.Hash(password)
		require.Conditionf(t,
			func() bool { return !slices.Contains(hash[0:i], string(password)) },
			`too identical hash: "%s"`, h)

		hash = append(hash, string(h))
	}
}

func TestBCryptHasher_Compare(t *testing.T) {
	args := []tab.Args{
		{
			"@not match",
			[]byte("message"),
			[]byte("$2a$12$C9x45xiasdp1VzID18TnDuGmEE9Hw3rDOaj9Er6o.AMRUNI1BEzoO"),
			errors.New("crypto/bcrypt: hashedPassword is not the hash of the given password"),
		},
		{
			"@match",
			[]byte("message"),
			[]byte("$2a$12$C9x45xiAsdp1VzID18TnDuGmEE9Hw3rDOaj9Er6o.AMRUNI1BEzoO"),
			nil,
		},
	}
	test := func(t *testing.T, password, hash []byte, eErr error) {
		aErr := hasher.Compare(password, hash)
		if eErr != nil {
			require.Error(t, aErr)
			assert.EqualError(t, aErr, eErr.Error())
		} else {
			assert.NoError(t, aErr)
		}
	}
	tab.RunWithArgs(t, args, test)
}
