package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
)

// MaxOTPLength is the maximun character length that OTP can be set to in the library
const MaxOTPLength = 8

// Hasher provides a custom hashing implementation for a OTP
type Hasher struct {
	// HashName is unique identifier for this hashing implementation
	HashName string
	// Digest is a function that returns a `hash.Hash` when called
	Digest func() hash.Hash
}

type formattter struct {
	createFormatString func(length int) string
	calculateRemainder func(binCode, length int) int
}

var sha1Hasher = &Hasher{HashName: "sha1", Digest: sha1.New}

var decFormatter = &formattter{
	createFormatString: func(length int) string { return fmt.Sprintf("%%0%dd", length) },
	calculateRemainder: func(binCode, length int) int { return binCode % int(math.Pow10(length)) },
}

var hexFormatter = &formattter{
	createFormatString: func(length int) string { return fmt.Sprintf("%%0%dx", length) },
	calculateRemainder: func(binCode, length int) int { return binCode >> (32 - 4*uint(length)) },
}

// otp knows how to generates OTPs
type otp struct {
	otpOptions
	secret []byte // secret in binary formats
}

type otpOptions struct {
	length       int         // number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
	interval     int         // the interval at which a TOTP changes its value in seconds
	hasher       *Hasher     // digest function to use in the HMAC
	formatter    *formattter // creates the format string and calculates the binCode remainder for the correct output
	formatString string      // formats the final output
}

var defaultOTPOptions = otpOptions{
	length:    6,
	interval:  30,
	hasher:    sha1Hasher,
	formatter: decFormatter,
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
		o.formatter = hexFormatter
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

func newOTP(secret []byte, opt ...OTPOption) (*otp, error) {
	opts := defaultOTPOptions

	if err := opts.applyOpts(opt); err != nil {
		return nil, err
	}

	opts.formatString = opts.formatter.createFormatString(opts.length)

	o := &otp{
		otpOptions: opts,
		secret:     secret,
	}
	return o, nil
}

// generateOTP according to https://tools.ietf.org/html/rfc4226#section-5
// HOTP(K,C) = Truncate(HMAC(K,C))
func (o *otp) generateOTP(movingFactor int) (string, error) {
	// Step 1: Generate an HMAC value
	hasher := hmac.New(o.hasher.Digest, o.secret)
	if _, err := hasher.Write(itob(movingFactor)); err != nil {
		return "", err
	}
	hmacHash := hasher.Sum(nil)

	// Step 2: Generate 4-bytes (Dynamic Truncation)
	// Step 3: Compute an HOTP value
	// Calculate the byte array offset from the last 4 bits in the hash (0 <= offset <= 15) and then convert the
	// four bytes after the offset to a 31-bit, unsigned, big-endian integer (the first byte is masked with a 0x7f)
	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := int(binary.BigEndian.Uint32(hmacHash[offset:]) & 0x7f_ff_ff_ff)

	// Calculate the remainder to get an integer of the correct length
	code = o.formatter.calculateRemainder(code, o.length)

	// Format the integer as a string
	return fmt.Sprintf(o.formatString, code), nil
}
