# GOTP - The Golang One-Time Password Library

[![build-status][build-status]][build-status] ![MIT License][license-badge]
[![codecov](https://codecov.io/gh/diebietse/gotp/branch/master/graph/badge.svg)](https://codecov.io/gh/diebietse/gotp)

GOTP is a Golang package for generating and verifying one-time passwords. It can be used to implement two-factor (2FA) or multi-factor (MFA) authentication methods in anywhere that requires users to log in.

Open MFA standards are defined in [RFC 4226][rfc-4226] (HOTP: An HMAC-Based One-Time Password Algorithm) and in [RFC 6238][rfc-6238] (TOTP: Time-Based One-Time Password Algorithm). GOTP implements server-side support for both of these standards.

GOTP was inspired by [PyOTP][py-otp].

This fork provides the functionality to produce OTPs with a hexadecimal output format.

## Installation

```console
go get github.com/diebietse/gotp/v2
```

## Usage

Check API docs at <https://godoc.org/github.com/diebietse/gotp>

### Time-based OTPs

```Go
secret, _ := gotp.DecodeBase32("4S62BZNFXXSZLCRO")
totp, _ := gotp.NewTOTP(secret)
totp.Now()  // current otp '123456'
totp.At(1524486261)  // otp of timestamp 1524486261 '123456'

// OTP verified for a given timestamp
totp.Verify("492039", 1524486261)  // true
totp.Verify("492039", 1520000000)  // false

// generate a provisioning uri
totp.ProvisioningURI("demoAccountName", "issuerName")
// otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
```

### Counter-based OTPs

```Go
secret, _ := gotp.DecodeBase32("4S62BZNFXXSZLCRO")
hotp, _ := gotp.NewHOTP(secret)
hotp.At(0)  // '944181'
hotp.At(1)  // '770975'

// OTP verified for a given counter
hotp.Verify("944181", 0)  // true
hotp.Verify("944181", 1)  // false

// generate a provisioning uri
hotp.ProvisioningURI("demoAccountName", "issuerName", 1)
// otpauth://hotp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&counter=1&issuer=issuerName
```

### Hex HOTP Output Example

```Go
secret, _ := gotp.DecodeBase32("4S62BZNFXXSZLCRO")
hotp, _ := gotp.NewHOTP(secret, FormatHex())
hotp.At(0)  // '0e6835'
hotp.At(1)  // '0bc39f'

// OTP verified for a given timestamp
hotp.Verify("0e6835", 0)  // true
hotp.Verify("0e6835", 1)  // false
```

### Generate random secret

```Go
secretLength := 16
gotp.RandomBase32Secret(secretLength) // LMT4URYNZKEWZRAA
```

### Google Authenticator Compatible

GOTP works with the Google Authenticator iPhone and Android app, as well as other OTP apps like Authy.
GOTP includes the ability to generate provisioning URIs for use with the QR Code
scanner built into these MFA client apps via `otpObj.ProvisioningUri` method:

```Go
secret, _ := gotp.DecodeBase32("4S62BZNFXXSZLCRO")
totp, _ := gotp.NewTOTP(secret)
totp.ProvisioningUri("demoAccountName", "issuerName")
// otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName

secret, _ := gotp.DecodeBase32("4S62BZNFXXSZLCRO")
hotp, _ := gotp.NewHOTP(secret)
hotp.ProvisioningUri("demoAccountName", "issuerName", 1)
// otpauth://hotp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&counter=1&issuer=issuerName
```

This URL can then be rendered as a QR Code which can then be scanned and added to the users list of OTP credentials.

### Working example

Scan the following barcode with your phone's OTP app (e.g. Google Authenticator):

![Demo](https://user-images.githubusercontent.com/5506906/39129827-0f12b582-473e-11e8-9c19-5e4f071eed26.png)

Now run the following and compare the output:

```Go
package main

import (
	"fmt"
	gotp "github.com/diebietse/gotp/v2"
)

func main() {
	secret, _ := gotp.DecodeBase32("4S62BZNFXXSZLCRO")
	totp, _ := gotp.NewTOTP(secret)
	fmt.Println("Current OTP is", totp.Now())
}
```

## License

GOTP is licensed under the [MIT License][license]

[build-status]: https://travis-ci.org/diebietse/gotp.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-MIT-000000.svg
[rfc-4226]: https://tools.ietf.org/html/rfc4226 "RFC 4226"
[rfc-6238]: https://tools.ietf.org/html/rfc6238 "RFC 6238"
[py-otp]: https://github.com/pyotp/pyotp
[license]: https://github.com/diebietse/gotp/blob/master/LICENSE
