package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
	"math"
)

type Hasher struct {
	HashName string
	Digest   func() hash.Hash
}

type OTP struct {
	secret     []byte  // secret in binary format
	digits     int     // number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
	hasher     *Hasher // digest function to use in the HMAC (expected to be sha1)
	formatting string  // Saves the format an OTP is generated with
	format     Format
}

// Format sets the output format of the OTP
type Format int

const (
	Unknown Format = iota
	FormatDec
	FormatHex
)

// MaxOTPLength set the character length limit of the library
const MaxOTPLength = 8

func newOTP(secret []byte, digits int, hasher *Hasher, format Format) (*OTP, error) {
	if digits < 0 || digits > MaxOTPLength {
		return nil, fmt.Errorf("OTP length must be between 0 and %d characters", MaxOTPLength)
	}

	if hasher == nil {
		hasher = &Hasher{
			HashName: "sha1",
			Digest:   sha1.New,
		}
	}

	var formatting string
	switch format {
	case FormatDec:
		formatting = fmt.Sprintf("%%0%dd", digits)
	case FormatHex:
		formatting = fmt.Sprintf("%%0%dx", digits)
	default:
		return nil, fmt.Errorf("unknown output format selected: %v", format)
	}

	otp := &OTP{
		secret:     secret,
		digits:     digits,
		hasher:     hasher,
		formatting: formatting,
		format:     format,
	}
	return otp, nil
}

/*
params
    input: the HMAC counter value to use as the OTP input. Usually either the counter, or the computed integer based on the Unix timestamp
*/
func (o *OTP) generateOTP(input int) (string, error) {
	hasher := hmac.New(o.hasher.Digest, o.secret)
	if _, err := hasher.Write(Itob(input)); err != nil {
		return "", err
	}

	hmacHash := hasher.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	switch o.format {
	case FormatDec:
		code = code % int(math.Pow10(o.digits))
	case FormatHex:
		code = code >> (32 - 4*uint(o.digits))
	}

	return fmt.Sprintf(o.formatting, code), nil
}
