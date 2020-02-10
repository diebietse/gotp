package gotp

import (
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getDefaultTOTP(t *testing.T) *TOTP {
	secret, err := DecodeSecretBase32("4S62BZNFXXSZLCRO")
	assert.NoError(t, err)
	hotp, err := NewDefaultTOTP(secret)
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
	secret, err := DecodeSecretBase32("4S62BZNFXXSZLCRO")
	assert.NoError(t, err)
	otpHex, err := NewTOTP(secret, 6, 30, nil, FormatHex)
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

func TestTOTP_RFCTestValuesSHA1(t *testing.T) {
	var rfc6238TestSecret = []byte("12345678901234567890")

	otpDec, err := NewTOTP(rfc6238TestSecret, 8, 30, nil, FormatDec)
	assert.NoError(t, err)

	otp, err := otpDec.At(59)
	assert.NoError(t, err, "OTP generation failed")
	assert.Equal(t, "94287082", otp)

	// Test data from https://tools.ietf.org/html/rfc6238#appendix-B
	tests := []struct {
		timestep int
		result   string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, test := range tests {
		otp, err := otpDec.At(test.timestep)
		assert.NoError(t, err, "OTP generation failed")
		assert.Equal(t, test.result, otp)
	}
}

func TestTOTP_RFCTestValuesSHA256(t *testing.T) {
	var rfc6238TestSecret = []byte("12345678901234567890123456789012")

	hasher := &Hasher{HashName: "sha256", Digest: sha256.New}
	otpDec, err := NewTOTP(rfc6238TestSecret, 8, 30, hasher, FormatDec)
	assert.NoError(t, err)

	otp, err := otpDec.At(59)
	assert.NoError(t, err, "OTP generation failed")
	assert.Equal(t, "46119246", otp)

	// Test data from https://tools.ietf.org/html/rfc6238#appendix-B
	tests := []struct {
		timestep int
		result   string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}

	for _, test := range tests {
		otp, err := otpDec.At(test.timestep)
		assert.NoError(t, err, "OTP generation failed")
		assert.Equal(t, test.result, otp)
	}
}

func TestTOTP_RFCTestValuesSHA512(t *testing.T) {
	var rfc6238TestSecret = []byte("1234567890123456789012345678901234567890123456789012345678901234")
	hasher := &Hasher{HashName: "sha512", Digest: sha512.New}

	otpDec, err := NewTOTP(rfc6238TestSecret, 8, 30, hasher, FormatDec)
	assert.NoError(t, err)

	// Test data from https://tools.ietf.org/html/rfc6238#appendix-B
	tests := []struct {
		timestep int
		result   string
	}{
		{59, "90693936"},
		{1111111109, "25091201"},
		{1111111111, "99943326"},
		{1234567890, "93441116"},
		{2000000000, "38618901"},
		{20000000000, "47863826"},
	}

	for _, test := range tests {
		otp, err := otpDec.At(test.timestep)
		assert.NoError(t, err, "OTP generation failed")
		assert.Equal(t, test.result, otp)
	}
}
