package gotp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// otpTypeTOTP is the Time Based OTP type
	otpTypeTOTP = "totp"
	// otpTypeHOTP is the Counter Based OTP type
	otpTypeHOTP = "hotp"
)

// buildURI returns the provisioning URI for a OTP with the given values.
// This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
func buildURI(otpType, secret, accountName, issuerName, algorithm string, initialCount, digits, period int) (string, error) {
	if otpType != otpTypeHOTP && otpType != otpTypeTOTP {
		return "", fmt.Errorf("otp type error, got %v", otpType)
	}

	urlParams := make([]string, 0)
	urlParams = append(urlParams, "secret="+secret)
	if otpType == otpTypeHOTP {
		urlParams = append(urlParams, fmt.Sprintf("counter=%d", initialCount))
	}
	label := url.QueryEscape(accountName)
	if issuerName != "" {
		issuerNameEscape := url.QueryEscape(issuerName)
		label = issuerNameEscape + ":" + label
		urlParams = append(urlParams, "issuer="+issuerNameEscape)
	}
	if algorithm != "" && algorithm != "sha1" {
		urlParams = append(urlParams, "algorithm="+strings.ToUpper(algorithm))
	}
	if digits != 0 && digits != 6 {
		urlParams = append(urlParams, fmt.Sprintf("digits=%d", digits))
	}
	if period != 0 && period != 30 {
		urlParams = append(urlParams, fmt.Sprintf("period=%d", period))
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, label, strings.Join(urlParams, "&")), nil
}

// currentTimestamp get the current timestamp in unix format
func currentTimestamp() int {
	return int(time.Now().Unix())
}

// itob converts an integer to a byte array
func itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}

// RandomSecret generate a random []byte secret of given length
func RandomSecret(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	return b, err
}

// DecodeBase32 decodes a base32 string and returns a byte array or error if it is not a valid base32 string
func DecodeBase32(secret string) ([]byte, error) {
	missingPadding := len(secret) % 8
	if missingPadding != 0 {
		secret = secret + strings.Repeat("=", 8-missingPadding)
	}
	bytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// EncodeBase32 encodes a byte array into a base32 string
func EncodeBase32(secret []byte) string {
	return base32.StdEncoding.EncodeToString(secret)
}
