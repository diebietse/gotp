package gotp

import "time"

// TOTP is the time-based OTP counters.
type TOTP struct {
	*OTP
	interval int
}

// NewTOTP returns an TOTP struct.
// If hasher is set to nil, the hasher defaults to SHA1.
func NewTOTP(secret []byte, digits, interval int, hasher *Hasher, format Format) (*TOTP, error) {
	otp, err := newOTP(secret, digits, hasher, format)
	if err != nil {
		return nil, err
	}
	return &TOTP{OTP: otp, interval: interval}, nil
}

// NewDefaultTOTP returns an TOTP struct with the given secret and set defaults.
// The digit count is 6, interval 30, hasher SHA1 and format is decimal output.
func NewDefaultTOTP(secret []byte) (*TOTP, error) {
	return NewTOTP(secret, 6, 30, nil, FormatDec)
}

// At generates the time OTP of given timestamp.
func (t *TOTP) At(timestamp int) (string, error) {
	return t.generateOTP(t.timecode(timestamp))
}

// Now generates the current time OTP.
func (t *TOTP) Now() (string, error) {
	return t.At(currentTimestamp())
}

// NowWithExpiration generates the current time OTP and expiration time.
func (t *TOTP) NowWithExpiration() (string, int64, error) {
	interval64 := int64(t.interval)
	timeCodeInt64 := time.Now().Unix() / interval64
	expirationTime := (timeCodeInt64 + 1) * interval64
	otp, err := t.generateOTP(int(timeCodeInt64))
	return otp, expirationTime, err
}

/*
Verify OTP.

params:
    otp:         the OTP to check against
    timestamp:   time to check OTP at
*/
func (t *TOTP) Verify(otp string, timestamp int) (bool, error) {
	refOTP, err := t.At(timestamp)
	if err != nil {
		return false, err
	}
	return otp == refOTP, nil
}

/*
ProvisioningURI returns the provisioning URI for the OTP.
This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.

See also:
    https://github.com/google/google-authenticator/wiki/Key-Uri-Format

params:
    accountName: name of the account
    issuerName:  the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator

returns: provisioning URI
*/
func (t *TOTP) ProvisioningURI(accountName, issuerName string) (string, error) {
	return BuildURI(
		OTPTypeTOTP,
		EncodeSecretBase32(t.secret),
		accountName,
		issuerName,
		t.hasher.HashName,
		0,
		t.digits,
		t.interval)
}

func (t *TOTP) timecode(timestamp int) int {
	return timestamp / t.interval
}
