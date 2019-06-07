package gotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func getDefaultTOTP(t *testing.T) *TOTP {
	hotp, err := NewDefaultTOTP("4S62BZNFXXSZLCRO")
	assert.NoError(t, err)
	return hotp
}

func TestTOTP_At(t *testing.T) {
	totp := getDefaultTOTP(t)
	assert.Equal(t, totp.Now(), totp.At(currentTimestamp()))
}

func TestTOTP_NowWithExpiration(t *testing.T) {
	totp := getDefaultTOTP(t)
	otp, exp := totp.NowWithExpiration()
	cts := currentTimestamp()
	assert.Equal(t, otp, totp.Now())
	assert.Equal(t, totp.At(cts+30), totp.At(int(exp)))
}

func TestTOTP_Verify(t *testing.T) {
	totp := getDefaultTOTP(t)
	assert.True(t, totp.Verify("179394", 1524485781))
}

func TestTOTP_ProvisioningUri(t *testing.T) {
	totp := getDefaultTOTP(t)
	expect := "otpauth://totp/github:xlzd?secret=4S62BZNFXXSZLCRO&issuer=github"
	uri := totp.ProvisioningURI("xlzd", "github")
	assert.Equal(t, expect, uri)
}

func TestTOTP_NowWithExpirationHex(t *testing.T) {
	otpHex, err := NewTOTP("4S62BZNFXXSZLCRO", 6, 30, nil, FormatHex)
	assert.NoError(t, err)
	otp, exp := otpHex.NowWithExpiration()
	cts := currentTimestamp()
	assert.Equal(t, otp, otpHex.Now())
	assert.Equal(t, otpHex.At(cts+30), otpHex.At(int(exp)))
}
