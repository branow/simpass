package services_test

import (
	"slices"
	"testing"

	. "github.com/branow/simpass/services"
	"github.com/branow/tabtest/tab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cipher Cipher = AES256GCMCipher{}

func TestAES256GCMCipher(t *testing.T) {
	n := 10_000
	plaintext := "Some very important information should be here"
	key := cipher.GenerateKeyHex()

	cts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ciphertext, err := cipher.EncryptHex(key, plaintext)
		require.NoError(t, err)
		plaintext2, err := cipher.DecryptHex(key, ciphertext)
		require.NoError(t, err)
		require.Equal(t, plaintext, plaintext2)

		require.Condition(t,
			func() (success bool) { return !slices.Contains(cts[:i], ciphertext) },
			"too identical ciphertexts: %s", ciphertext)
		cts = append(cts, ciphertext)
	}
}

func TestAES256GCMCipher_GenerateKeyHex(t *testing.T) {
	size := 10_000
	keys := make([]string, 0, size)
	for i := 0; i < size; i++ {
		key := cipher.GenerateKeyHex()
		require.Conditionf(t,
			func() bool { return !slices.Contains(keys[0:i], key) },
			`too identical keys: "%s"`, key)

		require.Equalf(t, AES256KeyLen*2, len(key),
			`invalid key length: expected=%d, actual=%d`, AES256KeyLen*2, len(key))

		keys = append(keys, key)
	}
}

func TestAES256GCMCipher_AdjustKeyHex(t *testing.T) {
	args := []tab.Args{
		{
			"@equal",
			"$]jEm}-fK=Q=pLtRr6NZFOfl5%$,Gk}z",
			"245d6a456d7d2d664b3d513d704c745272364e5a464f666c3525242c476b7d7a",
		},
		{
			"@short",
			"$]jEm}-fK=Q=pLtRr6NZ",
			"245d6a456d7d2d664b3d513d704c745272364e5a000000000000000000000000",
		},
		{
			"@long",
			"3H-r3adYekO^Q3AM,0JnQ@OXa7)y4x+S}plz]S",
			"b0b899ec90b46459656b4f5e5133414d2c304a6e51404f586137297934782b53",
		},
	}
	tab.RunWithArgs(t, args, func(t *testing.T, key string, exp string) {
		act := cipher.AdjustKeyHex(key)
		assert.Equal(t, exp, act)
	})
}

func TestAES256GCMCipher_EncryptHex(t *testing.T) {
	args := []tab.Args{
		{
			"@invalid encoding",
			"s3kr3tp4ssw0rd",
			"encoding/hex: invalid byte: U+0073 's'",
		},
		{
			"@invalid key length",
			"666a6c7361646b66666b6c6473616a6673616c6b66736b616a3635663473613631",
			KeyLengthErr{32, 33}.Error(),
		},
	}
	tab.RunWithArgs(t, args, func(t *testing.T, key, errMsg string) {
		_, err := cipher.EncryptHex(key, "")
		if err != nil {
			assert.EqualError(t, err, errMsg)
		} else if len(errMsg) == 0 {
			assert.Conditionf(t, func() bool { return len(errMsg) == 0 }, "expected errMsg: %s", errMsg)
		}
	})
}

func TestAES256GCMCipher_DecryptHex(t *testing.T) {
	args := []tab.Args{
		{
			"@invalid encoding",
			"s3kr3tp4ssw0rd",
			"fjdklsaj92u2kfldjfskafhusihfiskf",
			"encoding/hex: invalid byte: U+0073 's'\nencoding/hex: invalid byte: U+006A 'j'",
		},
		{
			"@invalid key length",
			"666a6c7361646b66666b6c6473616a6673616c6b66736b616a3635663473613631",
			"90aff492e8564d5d69f8150c6b23dc4fbb4f28700bdb59e12e1b41b8e789825b853a23bd90b777c884c447672ba48f",
			KeyLengthErr{32, 33}.Error(),
		},
		{
			"@invalid ciphertext",
			"666a6c7361646b66666b6c6473616a6673616c6b66736b616a36356634736136",
			"1190aff492e8564d5d69f8150c6b23dc4fbb4f28700bdb59e12e1b41b8e789825b853a23bd90b777c884c447672ba48f",
			"cipher: message authentication failed",
		},
	}
	tab.RunWithArgs(t, args, func(t *testing.T, key, ciphertext, errMsg string) {
		_, err := cipher.DecryptHex(key, ciphertext)
		if err != nil {
			assert.EqualError(t, err, errMsg)
		} else if len(errMsg) == 0 {
			assert.Conditionf(t, func() bool { return len(errMsg) == 0 }, "expected errMsg: %s", errMsg)
		}
	})
}
