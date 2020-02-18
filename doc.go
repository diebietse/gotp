/*
Package gotp is a package for generating and verifying one-time passwords.

It can be used to implement two-factor (2FA) or multi-factor (MFA) authentication methods anywhere that requires users to log in.

Open MFA standards are defined in [RFC 4226][rfc-4226] (HOTP: An HMAC-Based One-Time Password Algorithm)
and in [RFC 6238][rfc-6238] (TOTP: Time-Based One-Time Password Algorithm). GOTP implements server-side support for both of these standards.

GOTP was inspired by [PyOTP][py-otp].

This fork provides a cleaner API and the functionality to produce OTPs with a hexadecimal output format.
*/
package gotp
