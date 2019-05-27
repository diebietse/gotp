package gotp

import (
	"testing"
)

var hotp = NewDefaultHOTP("4S62BZNFXXSZLCRO")

func TestHOTP_At(t *testing.T) {
	otp := hotp.At(12345)
	if "194001" != otp {
		t.Error("HOTP generate otp error")
	}
}

func TestHOTP_Verify(t *testing.T) {
	if !hotp.Verify("194001", 12345) {
		t.Error("verify faild")
	}
}

func TestHOTP_Hex(t *testing.T) {
	otpHex := NewHOTP("KZOSZD7X6RG7HWZUQI2KBJULFU", 8, nil, FormatHex)
	otp := otpHex.At(0)
	if "07a45595" != otp {
		t.Errorf("HOTP generate otp error: %v", otp)
	}
}
