package gotp

// HOTP generates usage counter based OTPs
type HOTP struct {
	*otp
}

// NewHOTP returns a HOTP struct with the given secret and set defaults.
// The digit count is 6, hasher SHA1 and format is decimal output.
func NewHOTP(secret []byte, opt ...OTPOption) (*HOTP, error) {
	otp, err := newOTP(secret, opt...)
	if err != nil {
		return nil, err
	}
	return &HOTP{otp: otp}, nil

}

// At generates the OTP for the given `count` offset.
func (h *HOTP) At(count int) (string, error) {
	return h.generateOTP(count)
}

// Verify verifies if a given OTP is valid at a given `count` offset
func (h *HOTP) Verify(otp string, count int) (bool, error) {
	refOTP, err := h.At(count)
	if err != nil {
		return false, err
	}
	return otp == refOTP, nil
}

// ProvisioningURI returns the provisioning URI for the OTP.
// This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.
//
// It can be given a human readable "accountName" and "issuerName", as well as an "initialCount" for the OTP generation.
//
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
func (h *HOTP) ProvisioningURI(accountName, issuerName string, initialCount int) (string, error) {
	return buildURI(
		otpTypeHOTP,
		EncodeBase32(h.secret),
		accountName,
		issuerName,
		h.hasher.HashName,
		initialCount,
		h.length,
		0)
}
