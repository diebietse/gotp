package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
)

// MaxOTPLength set the character length limit of the library
const MaxOTPLength = 8

const (
	formatDec = iota
	formatHex
)

type Hasher struct {
	HashName string
	Digest   func() hash.Hash
}

var sha1Hasher = &Hasher{HashName: "sha1", Digest: sha1.New}

type OTP struct {
	otpOptions
	secret []byte // secret in binary formats
}

type otpOptions struct {
	length   int     // number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
	interval int     // the interval at which a TOTP changes its value in seconds
	hasher   *Hasher // digest function to use in the HMAC (expected to be sha1)
	format   int
}

var defaultOTPOptions = otpOptions{
	length:   6,
	interval: 30,
	hasher:   sha1Hasher,
	format:   formatDec,
}

type OTPOption func(*otpOptions) error

func WithLength(l int) OTPOption {
	return func(o *otpOptions) error {
		if l < 0 || l > MaxOTPLength {
			return fmt.Errorf("OTP length %d is not between 0 and %d characters", l, MaxOTPLength)
		}
		o.length = l
		return nil
	}
}

func WithHasher(hasher *Hasher) OTPOption {
	return func(o *otpOptions) error {
		o.hasher = hasher
		return nil
	}
}

func WithInterval(i int) OTPOption {
	return func(o *otpOptions) error {
		if i < 0 {
			return fmt.Errorf("TOTP interval %d is not greater than 0", i)
		}
		o.interval = i
		return nil
	}
}

func FormatHex() OTPOption {
	return func(o *otpOptions) error {
		o.format = formatHex
		return nil
	}
}

func (o *otpOptions) applyOpts(opts []OTPOption) error {
	var errorStrings []string
	for _, opt := range opts {
		if err := opt(o); err != nil {
			errorStrings = append(errorStrings, err.Error())
		}
	}

	if len(errorStrings) == 0 {
		return nil
	}
	return errors.New(strings.Join(errorStrings, ", "))
}

func newOTP(secret []byte, opt ...OTPOption) (*OTP, error) {
	opts := defaultOTPOptions

	if err := opts.applyOpts(opt); err != nil {
		return nil, err
	}

	otp := &OTP{
		otpOptions: opts,
		secret:     secret,
	}
	return otp, nil
}

/*
params
    input: the HMAC counter value to use as the OTP input. Usually either the counter, or the computed integer based on the Unix timestamp
*/
func (o *OTP) generateOTP(input int) (string, error) {
	hasher := hmac.New(o.hasher.Digest, o.secret)
	if _, err := hasher.Write(itob(input)); err != nil {
		return "", err
	}

	hmacHash := hasher.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	var formatting string
	switch o.format {
	case formatHex:
		formatting = fmt.Sprintf("%%0%dx", o.length)
		code = code >> (32 - 4*uint(o.length))
	default: // formatDec
		formatting = fmt.Sprintf("%%0%dd", o.length)
		code = code % int(math.Pow10(o.length))
	}

	return fmt.Sprintf(formatting, code), nil
}
