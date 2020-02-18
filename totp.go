package gotp

import "time"

// TOTP generates time-based OTPs
type TOTP struct {
	*OTP
}

// NewTOTP returns a TOTP struct with the given secret and set defaults.
// The digit count is 6, interval 30, hasher SHA1 and format is decimal output.
func NewTOTP(secret []byte, opt ...OTPOption) (*TOTP, error) {
	otp, err := newOTP(secret, opt...)
	if err != nil {
		return nil, err
	}
	return &TOTP{OTP: otp}, nil
}

// At generates the time-based OTP for the given timestamp.
func (t *TOTP) At(timestamp int) (string, error) {
	return t.generateOTP(t.timecode(timestamp))
}

// Now generates the current time-based OTP.
func (t *TOTP) Now() (string, error) {
	return t.At(currentTimestamp())
}

// NowWithExpiration generates the current time-based OTP and expiration time.
func (t *TOTP) NowWithExpiration() (string, int64, error) {
	interval64 := int64(t.interval)
	timeCodeInt64 := time.Now().Unix() / interval64
	expirationTime := (timeCodeInt64 + 1) * interval64
	otp, err := t.generateOTP(int(timeCodeInt64))
	return otp, expirationTime, err
}

// Verify verifies if a given OTP is valid at a given timestamp
func (t *TOTP) Verify(otp string, timestamp int) (bool, error) {
	refOTP, err := t.At(timestamp)
	if err != nil {
		return false, err
	}
	return otp == refOTP, nil
}

// ProvisioningURI returns the provisioning URI for the TOTP.
// This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.
//
// It can be given a human readable `accountName` and `issuerName` for the TOTP generation
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
func (t *TOTP) ProvisioningURI(accountName, issuerName string) (string, error) {
	return buildURI(
		OTPTypeTOTP,
		EncodeBase32(t.secret),
		accountName,
		issuerName,
		t.hasher.HashName,
		0,
		t.length,
		t.interval)
}

func (t *TOTP) timecode(timestamp int) int {
	return timestamp / t.interval
}
