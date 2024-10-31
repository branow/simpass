package crypto_test

import (
	"crypto/rand"
	"slices"
	"testing"

	. "github.com/branow/simpass/crypto"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cipher = AES256GCMCipher{}

func TestAES256GCMCipher(t *testing.T) {
	n := 100
	key := cipher.GenerateKey()

	cts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		plaintext := make([]byte, 50)

		_, err := rand.Read(plaintext)
		if err != nil {
			require.NoError(t, err)
		}

		for j := 0; j < n; j++ {
			ciphertext, err := cipher.Encrypt(key, plaintext)
			require.NoError(t, err)
			plaintext2, err := cipher.Decrypt(key, ciphertext)
			require.NoError(t, err)

			require.Equal(t, plaintext, plaintext2)
			require.Condition(t,
				func() (success bool) { return !slices.Contains(cts[:j], string(ciphertext)) },
				"too identical ciphertexts: %s", ciphertext)

			cts = append(cts, string(ciphertext))
		}
	}
}

func TestAES256GCMCipher_GenerateKey(t *testing.T) {
	size := 10_000
	keys := make([]string, 0, size)
	for i := 0; i < size; i++ {
		key := cipher.GenerateKey()
		require.Conditionf(t,
			func() bool { return !slices.Contains(keys[0:i], string(key)) },
			`too identical keys: "%s"`, key)

		require.Equalf(t, AES256KeyLen, len(key),
			`invalid key length: expected=%d, actual=%d`, AES256KeyLen, len(key))

		keys = append(keys, string(key))
	}
}

func TestAES256GCMCipher_AdjustKey(t *testing.T) {
	args := []tab.Args{
		{
			"@perfect key",
			[]byte{
				12, 1, 35, 43, 1, 94, 0, 43,
				54, 32, 46, 65, 3, 2, 86, 104,
				4, 153, 200, 255, 235, 3, 67, 34,
				212, 6, 43, 90, 87, 45, 12, 1,
			},
			[]byte{
				12, 1, 35, 43, 1, 94, 0, 43,
				54, 32, 46, 65, 3, 2, 86, 104,
				4, 153, 200, 255, 235, 3, 67, 34,
				212, 6, 43, 90, 87, 45, 12, 1,
			},
		},
		{
			"@short key",
			[]byte{
				12, 1, 35, 43, 1, 94, 0, 43,
				54, 32, 46, 65, 3, 2, 86, 104,
				4, 153, 200, 255, 235, 3, 67, 34,
			},
			[]byte{
				12, 1, 35, 43, 1, 94, 0, 43,
				54, 32, 46, 65, 3, 2, 86, 104,
				4, 153, 200, 255, 235, 3, 67, 34,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
		},
		{
			"@long key",
			[]byte{
				12, 1, 35, 43, 1, 94, 0, 43,
				54, 32, 46, 65, 3, 2, 86, 104,
				4, 153, 200, 255, 235, 3, 67, 34,
				212, 6, 43, 90, 87, 45, 12, 1,
				212, 6, 43, 90, 87, 45, 12, 1,
			},
			[]byte{
				224, 7, 78, 133, 88, 139, 12, 44,
				54, 32, 46, 65, 3, 2, 86, 104,
				4, 153, 200, 255, 235, 3, 67, 34,
				212, 6, 43, 90, 87, 45, 12, 1,
			},
		},
	}
	tab.RunWithArgs(t, args, func(t *testing.T, key, exp []byte) {
		act := cipher.AdjustKey(key)
		assert.Equal(t, exp, act)
	})
}

func TestAES256GCMCipher_Encrypt(t *testing.T) {
	args := []tab.Args{
		{
			"@invalid key length",
			[]byte{23, 12, 203, 213, 152, 12},
			[]byte{},
			KeyLengthErr{32, 6},
		},
		{
			"@successful run",
			[]byte{
				12, 1, 35, 43, 1, 94, 0, 43,
				54, 32, 46, 65, 3, 2, 86, 104,
				4, 153, 200, 255, 235, 3, 67, 34,
				212, 6, 43, 90, 87, 45, 12, 1,
			},
			[]byte("some data"),
			nil,
		},
	}
	tab.RunWithArgs(t, args, func(t *testing.T, key, plaintext []byte, eErr error) {
		ciphertext, aErr := cipher.Encrypt(key, plaintext)
		if eErr != nil {
			assert.EqualError(t, aErr, eErr.Error())
		} else {
			assert.NoError(t, aErr)
		}
		assert.NotEqual(t, ciphertext, plaintext, "ciphertext and plaintext are the same")
	})
}

func TestAES256GCMCipher_Decrypt(t *testing.T) {
	args := []tab.Args{
		{
			"@invalid key length",
			[]byte{23, 12, 203, 213, 152, 12},
			KeyLengthErr{32, 6},
		},
	}
	tab.RunWithArgs(t, args, func(t *testing.T, key []byte, eErr error) {
		_, aErr := cipher.Decrypt(key, []byte{})
		if eErr != nil {
			assert.EqualError(t, aErr, eErr.Error())
		} else {
			assert.NoError(t, aErr)
		}
	})
}
