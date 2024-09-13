package argon2id_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/jordanocokoljic/argon2id"
)

func TestUseParameters(t *testing.T) {
	tests := []struct {
		iterations  uint32
		parallelism uint8
		keyLength   uint32
	}{
		{
			iterations:  0,
			parallelism: 1,
			keyLength:   1,
		},
		{
			iterations:  1,
			parallelism: 0,
			keyLength:   1,
		},
		{
			iterations:  1,
			parallelism: 1,
			keyLength:   0,
		},
	}

	for _, test := range tests {
		t.Run(
			fmt.Sprintf(
				"With t=%d, p=%d, len=%d",
				test.iterations, test.parallelism, test.keyLength,
			),
			func(t *testing.T) {
				defer func() {
					if r := recover(); r == nil {
						t.Fatal("no panic detected")
					}
				}()

				argon2id.UseParameters(
					test.iterations,
					1024,
					test.parallelism,
					test.keyLength,
					16,
				)
			})
	}

	t.Run("WithValidValues", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatal("panic detected")
			}
		}()

		argon2id.UseParameters(2, 1024, 1, 32, 16)
	})
}

func TestGenerateFromPassword(t *testing.T) {
	parameters := argon2id.OWASPMinimumParameters()
	plain := []byte("my secure password")

	t.Run("GeneratesUniqueHashes", func(t *testing.T) {
		hash1, err := argon2id.GenerateFromPassword(plain, parameters)
		if err != nil {
			t.Fatalf("error generating first hash: %s", err)
		}

		hash2, err := argon2id.GenerateFromPassword(plain, parameters)
		if err != nil {
			t.Fatalf("error generating second hash: %s", err)
		}

		if bytes.Equal(hash1, hash2) {
			t.Errorf("generated hashes were identical")
		}
	})

	t.Run("EmbedsParametersCorrectly", func(t *testing.T) {
		params := argon2id.UseParameters(2, 1024, 1, 16, 32)

		hash, err := argon2id.GenerateFromPassword(plain, params)
		if err != nil {
			t.Fatalf("error generating hash: %s", err)
		}

		str := string(hash)

		if !strings.HasPrefix(str, "$argon2id$") {
			t.Errorf("hash does not have correct prefix: %s", str)
		}

		if !strings.Contains(str, "$v=19$") {
			t.Errorf("hash does not contain version: %s", str)
		}

		if !strings.Contains(str, "$m=1024,t=2,p=1$") {
			t.Errorf("hash does not contain parameters: %s", str)
		}
	})
}

func TestCompareHashAndPassword(t *testing.T) {
	tests := []struct {
		name  string
		plain string
		hash  string
		err   error
	}{
		{
			name:  "WithMatch",
			plain: "my secure password",
			hash:  "$argon2id$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$cJLIY6cYngQeiUeydZKtGA",
			err:   nil,
		},
		{
			name:  "WithMismatch",
			plain: "not my secure password",
			hash:  "$argon2id$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$cJLIY6cYngQeiUeydZKtGA",
			err:   argon2id.ErrMismatchedHashAndPassword,
		},
		{
			name:  "WithInvalidHashedPassword",
			plain: "my secure password",
			hash:  "$2a$12$qqfeFauZRohHTmfvEVZmbO96u/ve3fFdvW/CcBynq2mmHGBl3X1ka",
			err:   argon2id.ErrInvalidHash,
		},
		{
			name:  "WithBadVersion",
			plain: "not my secure password",
			hash:  "$argon2id$v=20$m=1024,t=1,p=1$c29tZXNhbHQ$cJLIY6cYngQeiUeydZKtGA",
			err:   argon2id.ErrBadVersion,
		},
		{
			name:  "WithInvalidIterations",
			plain: "my secure password",
			hash:  "$argon2id$v=19$m=1024,t=0,p=1$c29tZXNhbHQ$cJLIY6cYngQeiUeydZKtGA",
			err:   argon2id.ErrInvalidHash,
		},
		{
			name:  "WithInvalidParallelism",
			plain: "my secure password",
			hash:  "$argon2id$v=19$m=1024,t=1,p=0$c29tZXNhbHQ$cJLIY6cYngQeiUeydZKtGA",
			err:   argon2id.ErrInvalidHash,
		},
		{
			name:  "WithOutOfRangeMemory",
			plain: "my secure password",
			hash:  "$argon2id$v=19$m=4294967296,t=1,p=1$c29tZXNhbHQ$cJLIY6cYngQeiUeydZKtGA",
			err:   argon2id.ErrInvalidHash,
		},
		{
			name:  "WithBadlyEncodedSalt",
			plain: "my secure password",
			hash:  "$argon2id$v=19$m=1024,t=1,p=1$c29tZ.XNhbHQ$cJLIY6cYngQeiUeydZKtGA",
			err:   argon2id.ErrInvalidHash,
		},
		{
			name:  "WithBadlyEncodedKey",
			plain: "my secure password",
			hash:  "$argon2id$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$cJLIY6cYngQei.UeydZKtGA",
			err:   argon2id.ErrInvalidHash,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := argon2id.CompareHashAndPassword([]byte(test.hash), []byte(test.plain))
			if err != test.err {
				t.Errorf("returned error was incorrect: %s", err)
			}
		})
	}
}

func TestInteropability(t *testing.T) {
	plain := []byte("my secure password")

	hash, err := argon2id.GenerateFromPassword(plain, argon2id.OWASPMinimumParameters())
	if err != nil {
		t.Fatalf("error occurred generating hash: %s", err)
	}

	err = argon2id.CompareHashAndPassword(hash, plain)
	if err != nil {
		t.Fatalf("comparison failed")
	}
}
