// Package argon2id provides utility functions for generating and verifying
// hashes using the Argon2 key derivation function.
package argon2id

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"unsafe"

	"golang.org/x/crypto/argon2"
)

// The Argon2 version that this library uses.
const Version = argon2.Version

// Reasonable memory magnitudes. GiB is the largest defined magnitude as the
// largest amount of memory that Argon2id can use is 3999 GiB.
const (
	KiB = 1
	MiB = 1024 * KiB
	GiB = 1024 * MiB
)

// The error returned from CompareHashAndPassword when a password and hash do
// not match.
var ErrMismatchedHashAndPassword = errors.New("argon2id: hashedPassword is not the hash of the given password")

// The error returned from CompareHashAndPassword when a hashed password is not
// a valid argon2id hash. This could be for a multitude of reasons, such as one
// or more of the parameters being invalid (out of range), the key or salt not
// being correctly encoded base64 values, or the hash being unparsable.
var ErrInvalidHash = errors.New("argon2id: hashedPassword is not a valid argon2id hash")

// The error returned from CompareHashAndPassword when a hashed password was
// generated with a different version of the argon2 key derivation function.
var ErrBadVersion = errors.New("argon2id: hashedPassword was generated with another version of argon2")

// The regex expression used to decode hashes.
var decode = regexp.MustCompile(`^\$argon2id\$v=(\d{2})\$m=(\d+),t=(\d+),p=(\d+)\$([a-zA-Z0-9+\/=]+)\$([a-zA-Z0-9+\/=]+)$`)

// Parameters defines the input parameters required by the Argon2id key
// derivation function.
type Parameters struct {
	iterations  uint32
	memory      uint32
	parallelism uint8
	keyLength   uint32
	saltLength  uint32
}

// UseParameters will return a new [Parameters] instance that can be used when
// deriving keys from a password. It will panic if the iterations, parallelism
// or key length are 0.
func UseParameters(
	iterations uint32,
	memory uint32,
	parallelism uint8,
	keyLength uint32,
	saltLength uint32,
) Parameters {
	if iterations == 0 {
		panic("argon2id: unable to create parameters: iterations cannot be 0")
	}

	if parallelism == 0 {
		panic("argon2id: unable to create parameters: parallelism cannot be 0")
	}

	if keyLength == 0 {
		panic("argon2id: unable to create parameters: keyLength cannot be 0")
	}

	return Parameters{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		saltLength:  saltLength,
		keyLength:   keyLength,
	}
}

// OWASPParameters will return a new [Parameters] instance that adheres to the
// OWASP suggestions[1] as of 2024/09/13. Because OWASP doesn't provide values
// for the salt and key length, these have been set at 128 and 256 bits
// respectively.
//
// [1]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
func OWASPParameters() Parameters {
	return Parameters{
		iterations:  2,
		memory:      19 * MiB,
		parallelism: 1,
		keyLength:   32,
		saltLength:  16,
	}
}

// GenerateFromPassword returns the Argon2id hash of the password based on the
// given configuration.
func GenerateFromPassword(password []byte, parameters Parameters) ([]byte, error) {
	salt := make([]byte, parameters.saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("argon2id: unable to generate salt for hash: %w", err)
	}

	key := argon2.IDKey(
		password, salt,
		parameters.iterations,
		parameters.memory,
		parameters.parallelism,
		parameters.keyLength,
	)

	encodedSalt := make([]byte, base64.RawStdEncoding.EncodedLen(len(salt)))
	base64.RawStdEncoding.Encode(encodedSalt, salt)

	encodedKey := make([]byte, base64.RawStdEncoding.EncodedLen(len(key)))
	base64.RawStdEncoding.Encode(encodedKey, key)

	var buffer bytes.Buffer
	_, err = fmt.Fprintf(
		&buffer,
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Version,
		parameters.memory,
		parameters.iterations,
		parameters.parallelism,
		encodedSalt,
		encodedKey,
	)

	if err != nil {
		return nil, fmt.Errorf("argon2id: unable to format hash: %w", err)
	}

	return buffer.Bytes(), nil
}

// CompareHashAndPassword compares an Argon2id hashed password with it's
// possible plaintext equivalent. Returns nil on success, or an error on
// failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	matches := decode.FindAllSubmatchIndex(hashedPassword, -1)
	if len(matches) == 0 {
		return ErrInvalidHash
	}

	index := matches[0][2:]
	str := unsafe.String(&hashedPassword[0], len(hashedPassword))

	version, _ := strconv.Atoi(str[index[0]:index[1]])
	if version != Version {
		return ErrBadVersion
	}

	memory, err := strconv.ParseUint(str[index[2]:index[3]], 10, 32)
	if err != nil {
		return ErrInvalidHash
	}

	iterations, err := strconv.ParseUint(str[index[4]:index[5]], 10, 32)
	if err != nil || iterations == 0 {
		return ErrInvalidHash
	}

	parallelism, err := strconv.ParseUint(str[index[6]:index[7]], 10, 8)
	if err != nil || parallelism == 0 {
		return ErrInvalidHash
	}

	salt := make([]byte, base64.RawStdEncoding.DecodedLen(index[9]-index[8]))
	_, err = base64.RawStdEncoding.Decode(salt, hashedPassword[index[8]:index[9]])
	if err != nil {
		return ErrInvalidHash
	}

	key := make([]byte, base64.RawStdEncoding.DecodedLen(index[11]-index[10]))
	_, err = base64.RawStdEncoding.Decode(key, hashedPassword[index[10]:index[11]])
	if err != nil {
		return ErrInvalidHash
	}

	compareKey := argon2.IDKey(password, salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(key)))
	if subtle.ConstantTimeCompare(key, compareKey) == 0 {
		return ErrMismatchedHashAndPassword
	}

	return nil
}
