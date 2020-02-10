package gotp

// HOTP is the HMAC-based OTP counters.
type HOTP struct {
	*OTP
}

// NewHOTP returns an HOTP struct.
// If hasher is set to nil, the hasher defaults to SHA1.
func NewHOTP(secret []byte, digits int, hasher *Hasher, format Format) (*HOTP, error) {
	otp, err := newOTP(secret, digits, hasher, format)
	if err != nil {
		return nil, err
	}
	return &HOTP{OTP: otp}, nil

}

// NewDefaultHOTP returns an HOTP struct with the given secret and set defaults.
// The digit count is 6, hasher SHA1 and format is decimal output.
func NewDefaultHOTP(secret []byte) (*HOTP, error) {
	return NewHOTP(secret, 6, nil, FormatDec)
}

// At generates the OTP for the given count.
func (h *HOTP) At(count int) (string, error) {
	return h.generateOTP(count)
}

/*
Verify OTP.

params:
    otp:   the OTP to check against
    count: the OTP HMAC counter
*/
func (h *HOTP) Verify(otp string, count int) (bool, error) {
	refOTP, err := h.At(count)
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
    accountName:  name of the account
    issuerName:   the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator
    initialCount: starting HMAC counter value

returns: provisioning URI
*/
func (h *HOTP) ProvisioningURI(accountName, issuerName string, initialCount int) (string, error) {
	return BuildURI(
		OTPTypeHOTP,
		EncodeSecretBase32(h.secret),
		accountName,
		issuerName,
		h.hasher.HashName,
		initialCount,
		h.digits,
		0)
}
