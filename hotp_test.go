package gotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func getDefaultHOTP(t *testing.T) *HOTP {
	hotp, err := NewDefaultHOTP("4S62BZNFXXSZLCRO")
	assert.NoError(t, err)
	return hotp
}

func TestHOTP_At(t *testing.T) {
	hotp := getDefaultHOTP(t)
	otp := hotp.At(12345)
	assert.Equal(t, "194001", otp)
}

func TestHOTP_Verify(t *testing.T) {
	hotp := getDefaultHOTP(t)
	assert.True(t, hotp.Verify("194001", 12345))
}

func TestHOTP_Hex(t *testing.T) {
	otpHex, err := NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", 8, nil, FormatHex)
	assert.NoError(t, err)
	otp := otpHex.At(0)
	assert.Equal(t, "07a45595", otp)
}

func TestHOTP_HexFive(t *testing.T) {
	otpHex, err := NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", 5, nil, FormatHex)
	assert.NoError(t, err)
	otp := otpHex.At(0)
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
