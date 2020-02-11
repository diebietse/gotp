package gotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var rfc4226TestSecret = []byte("12345678901234567890")

func getDefaultHOTP(t *testing.T) *HOTP {
	secret, err := DecodeSecretBase32("4S62BZNFXXSZLCRO")
	assert.NoError(t, err)
	hotp, err := NewHOTP(secret)
	assert.NoError(t, err)
	return hotp
}

func TestHOTP_At(t *testing.T) {
	hotp := getDefaultHOTP(t)
	otp, err := hotp.At(12345)
	assert.NoError(t, err, "OTP generation failed")
	assert.Equal(t, "194001", otp)
}

func TestHOTP_Verify(t *testing.T) {
	hotp := getDefaultHOTP(t)
	valid, err := hotp.Verify("194001", 12345)
	assert.NoError(t, err, "OTP verify failed")
	assert.True(t, valid)
}

func TestHOTP_Hex(t *testing.T) {
	secret, err := DecodeSecretBase32("KZOSZD7X6RG7HWZUQI2KBJULFU")
	assert.NoError(t, err)
	otpHex, err := NewHOTP(secret, WithLength(8), FormatHex())
	assert.NoError(t, err)
	otp, err := otpHex.At(0)
	assert.NoError(t, err, "OTP generation failed")
	assert.Equal(t, "07a45595", otp)
}

func TestHOTP_HexFive(t *testing.T) {
	secret, err := DecodeSecretBase32("KZOSZD7X6RG7HWZUQI2KBJULFU")
	assert.NoError(t, err)
	otpHex, err := NewHOTP(secret, WithLength(5), FormatHex())
	assert.NoError(t, err)
	otp, err := otpHex.At(0)
	assert.NoError(t, err, "OTP generation failed")
	assert.Equal(t, "07a45", otp)
}

func TestHOTP_InvalidLength(t *testing.T) {
	secret, err := DecodeSecretBase32("KZOSZD7X6RG7HWZUQI2KBJULFU")
	assert.NoError(t, err)
	_, err = NewHOTP(secret, WithLength(9), FormatHex())
	assert.Error(t, err)
	_, err = NewHOTP(secret, WithLength(-1), FormatHex())
	assert.Error(t, err)
}

func TestHOTP_RFCTestValues(t *testing.T) {
	otpDec, err := NewHOTP(rfc4226TestSecret)
	assert.NoError(t, err)

	// Expected results from https://tools.ietf.org/html/rfc4226#page-32
	expectedResults := []string{
		"755224",
		"287082",
		"359152",
		"969429",
		"338314",
		"254676",
		"287922",
		"162583",
		"399871",
		"520489",
	}

	for i, expectedResult := range expectedResults {
		otp, err := otpDec.At(i)
		assert.NoError(t, err, "OTP generation failed")
		assert.Equal(t, expectedResult, otp)
	}
}

func TestHOTP_HexRFCTestValues(t *testing.T) {
	otpHex, err := NewHOTP(rfc4226TestSecret, WithLength(8), FormatHex())

	assert.NoError(t, err)

	// Expected results from https://tools.ietf.org/html/rfc4226#page-32
	expectedResults := []string{
		"4c93cf18",
		"41397eea",
		"082fef30",
		"66ef7655",
		"61c5938a",
		"33c083d4",
		"7256c032",
		"04e5b397",
		"2823443f",
		"2679dc69",
	}

	for i, expectedResult := range expectedResults {
		otp, err := otpHex.At(i)
		assert.NoError(t, err, "OTP generation failed")
		assert.Equal(t, expectedResult, otp)
	}
}
