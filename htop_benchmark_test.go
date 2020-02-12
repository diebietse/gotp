package gotp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func BenchmarkHOTPAt_SHA1(b *testing.B) {
	var rfc6238TestSecret = []byte("12345678901234567890")

	hasher := &Hasher{HashName: "sha-1", Digest: sha1.New}
	otp, err := NewHOTP(rfc6238TestSecret, WithHasher(hasher))
	if err != nil {
		b.Errorf("Could not create default HOTP: %v", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := otp.At(i)
		if err != nil {
			b.Errorf("Could not generate OTP: %v", err)
		}
	}
}

func BenchmarkHOTPAt_SHA256(b *testing.B) {
	var rfc6238TestSecret = []byte("12345678901234567890123456789012")

	hasher := &Hasher{HashName: "sha256", Digest: sha256.New}
	otp, err := NewHOTP(rfc6238TestSecret, WithHasher(hasher))
	if err != nil {
		b.Errorf("Could not create default HOTP: %v", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := otp.At(i)
		if err != nil {
			b.Errorf("Could not generate OTP: %v", err)
		}
	}
}

func BenchmarkHOTPAt_SHA512(b *testing.B) {
	var rfc6238TestSecret = []byte("1234567890123456789012345678901234567890123456789012345678901234")

	hasher := &Hasher{HashName: "sha512", Digest: sha512.New}
	otp, err := NewHOTP(rfc6238TestSecret, WithHasher(hasher))
	if err != nil {
		b.Errorf("Could not create default HOTP: %v", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := otp.At(i)
		if err != nil {
			b.Errorf("Could not generate OTP: %v", err)
		}
	}
}

func BenchmarkNewHOTPAt_SHA1(b *testing.B) {
	var rfc6238TestSecret = []byte("12345678901234567890")
	hasher := &Hasher{HashName: "sha-1", Digest: sha1.New}

	for i := 0; i < b.N; i++ {
		otp, err := NewHOTP(rfc6238TestSecret, WithHasher(hasher))
		if err != nil {
			b.Errorf("Could not create default HOTP: %v", err)
		}
		_, err = otp.At(i)
		if err != nil {
			b.Errorf("Could not generate OTP: %v", err)
		}
	}
}

func BenchmarkNewHOTP_SHA256(b *testing.B) {
	var rfc6238TestSecret = []byte("12345678901234567890123456789012")
	hasher := &Hasher{HashName: "sha256", Digest: sha256.New}

	for i := 0; i < b.N; i++ {
		otp, err := NewHOTP(rfc6238TestSecret, WithHasher(hasher))
		if err != nil {
			b.Errorf("Could not create default HOTP: %v", err)
		}
		_, err = otp.At(i)
		if err != nil {
			b.Errorf("Could not generate OTP: %v", err)
		}
	}
}

func BenchmarkNewHOTP_SHA512(b *testing.B) {
	var rfc6238TestSecret = []byte("1234567890123456789012345678901234567890123456789012345678901234")

	hasher := &Hasher{HashName: "sha512", Digest: sha512.New}
	for i := 0; i < b.N; i++ {
		otp, err := NewHOTP(rfc6238TestSecret, WithHasher(hasher))
		if err != nil {
			b.Errorf("Could not create default HOTP: %v", err)
		}
		_, err = otp.At(i)
		if err != nil {
			b.Errorf("Could not generate OTP: %v", err)
		}
	}
}
