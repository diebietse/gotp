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

// MaxOTPLength is the maximun character length that OTP can be set to in the library
const MaxOTPLength = 8

const (
	formatDec = iota
	formatHex
)

// Hasher provides a custom hashing implementation for a OTP
type Hasher struct {
	// HashName is unique identifier for this hashing implementation
	HashName string
	// Digest is a function that returns a `hash.Hash` when called
	Digest func() hash.Hash
}

var sha1Hasher = &Hasher{HashName: "sha1", Digest: sha1.New}

// OTP knows how to generates OTPs
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

// OTPOption configures OTPs
type OTPOption func(*otpOptions) error

// WithLength make generated OTPs have the given length
func WithLength(l int) OTPOption {
	return func(o *otpOptions) error {
		if l < 0 || l > MaxOTPLength {
			return fmt.Errorf("OTP length %d is not between 0 and %d characters", l, MaxOTPLength)
		}
		o.length = l
		return nil
	}
}

// WithHasher lets OTPs be generated using the given hasher
func WithHasher(hasher *Hasher) OTPOption {
	return func(o *otpOptions) error {
		o.hasher = hasher
		return nil
	}
}

// WithInterval lets TOTPs have the given interval for changing its values
func WithInterval(i int) OTPOption {
	return func(o *otpOptions) error {
		if i < 0 {
			return fmt.Errorf("TOTP interval %d is not greater than 0", i)
		}
		o.interval = i
		return nil
	}
}

// FormatHex lets OTPs be returned in Hexadecimal format instead of Decimal format
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

func (o *OTP) generateOTP(movingFactor int) (string, error) {
	hasher := hmac.New(o.hasher.Digest, o.secret)
	if _, err := hasher.Write(itob(movingFactor)); err != nil {
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
