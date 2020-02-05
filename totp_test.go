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
	otpNow, err := totp.Now()
	assert.NoError(t, err, "OTP now generation failed")
	otpAt, err := totp.At(currentTimestamp())
	assert.NoError(t, err, "OTP at timestamp generation failed")
	assert.Equal(t, otpNow, otpAt)
}

func TestTOTP_NowWithExpiration(t *testing.T) {
	totp := getDefaultTOTP(t)
	otp, exp, err := totp.NowWithExpiration()
	assert.NoError(t, err, "OTP generation failed")
	cts := currentTimestamp()
	otpNow, err := totp.Now()
	assert.NoError(t, err, "OTP now generation failed")
	assert.Equal(t, otp, otpNow)
	otpAt30, err := totp.At(cts + 30)
	assert.NoError(t, err, "OTP at 30s offset generation failed")
	otpAtExp, err := totp.At(int(exp))
	assert.NoError(t, err, "OTP at expiry generation failed")
	assert.Equal(t, otpAt30, otpAtExp)
}

func TestTOTP_Verify(t *testing.T) {
	totp := getDefaultTOTP(t)
	valid, err := totp.Verify("179394", 1524485781)
	assert.NoError(t, err, "OTP verify failed")
	assert.True(t, valid)
}

func TestTOTP_ProvisioningUri(t *testing.T) {
	totp := getDefaultTOTP(t)
	expect := "otpauth://totp/github:xlzd?secret=4S62BZNFXXSZLCRO&issuer=github"
	uri, err := totp.ProvisioningURI("xlzd", "github")
	assert.NoError(t, err, "URI generation failed")
	assert.Equal(t, expect, uri)
}

func TestTOTP_NowWithExpirationHex(t *testing.T) {
	otpHex, err := NewTOTP("4S62BZNFXXSZLCRO", 6, 30, nil, FormatHex)
	assert.NoError(t, err)
	otp, exp, err := otpHex.NowWithExpiration()
	assert.NoError(t, err, "OTP generation failed")
	cts := currentTimestamp()

	otpNow, err := otpHex.Now()
	assert.NoError(t, err, "OTP now generation failed")
	assert.Equal(t, otp, otpNow)
	otpAt30, err := otpHex.At(cts + 30)
	assert.NoError(t, err, "OTP at 30s offset generation failed")
	otpAtExp, err := otpHex.At(int(exp))
	assert.NoError(t, err, "OTP at expiry generation failed")
	assert.Equal(t, otpAt30, otpAtExp)
}
