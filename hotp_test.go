package gotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var rfc4226TestSecret = encodeSecret([]byte("12345678901234567890"))

func getDefaultHOTP(t *testing.T) *HOTP {
	hotp, err := NewDefaultHOTP("4S62BZNFXXSZLCRO")
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
	otpHex, err := NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", 8, nil, FormatHex)
	assert.NoError(t, err)
	otp, err := otpHex.At(0)
	assert.NoError(t, err, "OTP generation failed")
	assert.Equal(t, "07a45595", otp)
}

func TestHOTP_HexFive(t *testing.T) {
	otpHex, err := NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", 5, nil, FormatHex)
	assert.NoError(t, err)
	otp, err := otpHex.At(0)
	assert.NoError(t, err, "OTP generation failed")
	assert.Equal(t, "07a45", otp)
}

func TestHOTP_InvalidLength(t *testing.T) {
	_, err := NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", 9, nil, FormatHex)
	assert.Error(t, err)
	_, err = NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", -1, nil, FormatHex)
	assert.Error(t, err)
}

func TestHOTP_InvalidSecret(t *testing.T) {
	_, err := NewHOTP("!@#$%^&*()", 8, nil, FormatHex)
	assert.Error(t, err)
}

func TestHOTP_InvalidFormat(t *testing.T) {
	_, err := NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", 5, nil, Unknown)
	assert.Error(t, err)
}

func TestHOTP_RFCTestValues(t *testing.T) {
	otpDec, err := NewDefaultHOTP(rfc4226TestSecret)
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
	otpHex, err := NewHOTP(rfc4226TestSecret, 8, nil, FormatHex)
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
