package gotp

import (
	"fmt"
)

func ExampleNewTOTP() {
	secret, err := DecodeSecretBase32("4S62BZNFXXSZLCRO")
	if err != nil {
		panic(err)
	}
	otp, err := NewTOTP(secret)
	if err != nil {
		panic(err)
	}

	otpAt, err := otp.At(0)
	if err != nil {
		panic(err)
	}
	fmt.Printf("one-time password of timestamp 0 is: %v\n", otpAt)
	uri, err := otp.ProvisioningURI("demoAccountName", "issuerName")
	if err != nil {
		panic(err)
	}
	fmt.Printf("uri: %s\n", uri)

	valid, err := otp.Verify("179394", 1524485781)
	if err != nil {
		panic(err)
	}
	fmt.Printf("otp is valid: %v\n", valid)
	// Output:
	// one-time password of timestamp 0 is: 944181
	// uri: otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
	// otp is valid: true
}

func ExampleTOTP_Now() {
	secret, err := DecodeSecretBase32("4S62BZNFXXSZLCRO")
	if err != nil {
		panic(err)
	}
	otp, err := NewTOTP(secret)
	if err != nil {
		panic(err)
	}
	currentOTP, err := otp.Now()
	if err != nil {
		panic(err)
	}
	fmt.Printf("current one-time password is: %v\n", currentOTP)
}

func ExampleNewHOTP() {
	secret, err := DecodeSecretBase32("4S62BZNFXXSZLCRO")
	if err != nil {
		panic(err)
	}
	otp, err := NewHOTP(secret)
	if err != nil {
		panic(err)
	}

	otpAt, err := otp.At(0)
	if err != nil {
		panic(err)
	}
	fmt.Printf("one-time password of counter 0 is: %v\n", otpAt)
	uri, err := otp.ProvisioningURI("demoAccountName", "issuerName", 1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("uri: %s\n", uri)

	valid, err := otp.Verify("944181", 0)
	if err != nil {
		panic(err)
	}
	fmt.Printf("otp is valid: %v\n", valid)

	// Output:
	// one-time password of counter 0 is: 944181
	// uri: otpauth://hotp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&counter=1&issuer=issuerName
	// otp is valid: true
}
