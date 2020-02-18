package gotp

import (
	"encoding/base32"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

const (
	// OTPTypeTOTP is the Time Based OTP type
	OTPTypeTOTP = "totp"
	// OTPTypeHOTP is the Counter Based OTP type
	OTPTypeHOTP = "hotp"
)

// buildURI returns the provisioning URI for a OTP with the given values.
// This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
func buildURI(otpType, secret, accountName, issuerName, algorithm string, initialCount, digits, period int) (string, error) {
	if otpType != OTPTypeHOTP && otpType != OTPTypeTOTP {
		return "", fmt.Errorf("otp type error, got %v", otpType)
	}

	urlParams := make([]string, 0)
	urlParams = append(urlParams, "secret="+secret)
	if otpType == OTPTypeHOTP {
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

// RandomBase32Secret generate a random base32 secret of given length
func RandomBase32Secret(length int) string {
	rand.Seed(time.Now().UnixNano())
	// spell-checker:disable-next-line
	letterRunes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

	bytes := make([]rune, length)

	for i := range bytes {
		bytes[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(bytes)
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
