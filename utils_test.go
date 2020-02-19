package gotp

// spell-checker:disable
import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testValidURI     = "otpauth://totp/SomeOrg:diebietse?secret=4S62BZNFXXSZLCRO&issuer=SomeOrg"
	testValidURILong = "otpauth://hotp/SomeOrg:diebietse?secret=4S62BZNFXXSZLCRO&counter=0&issuer=SomeOrg&algorithm=SHA256&digits=8&period=15"
)

func TestBuildUri(t *testing.T) {
	uri, err := buildURI(
		"totp",
		"4S62BZNFXXSZLCRO",
		"diebietse",
		"SomeOrg",
		"sha1",
		0,
		6,
		0,
	)
	assert.NoError(t, err, "URI building failed")
	assert.Equal(t, testValidURI, uri, "Generated URI did not match")
}

func TestBuildUri_nonDefaults(t *testing.T) {
	uri, err := buildURI(
		"hotp",
		"4S62BZNFXXSZLCRO",
		"diebietse",
		"SomeOrg",
		"sha256",
		0,
		8,
		15,
	)
	assert.NoError(t, err, "URI building failed")
	assert.Equal(t, testValidURILong, uri, "Generated URI did not match")
}

func TestBuildUri_fail(t *testing.T) {
	_, err := buildURI(
		"potp",
		"4S62BZNFXXSZLCRO",
		"diebietse",
		"SomeOrg",
		"sha1",
		0,
		6,
		0,
	)
	assert.Error(t, err, "invalid OTP standard did not cause an error")
}

func TestITob(t *testing.T) {
	i := 1524486261
	expect := []byte{0, 0, 0, 0, 90, 221, 208, 117}

	assert.Equal(t, string(expect), string(itob(i)), "Integer to byte array conversion failed")
}

func TestRandomSecretLength(t *testing.T) {
	length := 12
	secret, err := RandomSecret(length)
	assert.NoError(t, err)
	assert.Equal(t, length, len(secret), "Secret length did not match expected length")
}

func TestDecodeSecretBase32_Invalid(t *testing.T) {
	_, err := DecodeBase32("1")
	assert.Error(t, err)
}
