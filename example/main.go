package main

import (
	"fmt"

	"github.com/diebietse/gotp"
)

func main() {
	fmt.Println("Random secret:", gotp.RandomSecret(16))
	defaultTOTPUsage()
	defaultHOTPUsage()
}

func defaultTOTPUsage() {
	secret, err := gotp.DecodeSecretBase32("4S62BZNFXXSZLCRO")
	if err != nil {
		panic(err)
	}
	otp, err := gotp.NewDefaultTOTP(secret)
	if err != nil {
		panic(err)
	}

	currentOTP, err := otp.Now()
	if err != nil {
		panic(err)
	}

	fmt.Println("current one-time password is:", currentOTP)
	otpAt, err := otp.At(0)
	if err != nil {
		panic(err)
	}
	fmt.Println("one-time password of timestamp 0 is:", otpAt)
	fmt.Println(otp.ProvisioningURI("demoAccountName", "issuerName"))

	fmt.Println(otp.Verify("179394", 1524485781))
}

func defaultHOTPUsage() {
	secret, err := gotp.DecodeSecretBase32("4S62BZNFXXSZLCRO")
	if err != nil {
		panic(err)
	}
	otp, err := gotp.NewDefaultHOTP(secret)
	if err != nil {
		panic(err)
	}

	otpAt, err := otp.At(0)
	if err != nil {
		panic(err)
	}
	fmt.Println("one-time password of counter 0 is:", otpAt)
	fmt.Println(otp.ProvisioningURI("demoAccountName", "issuerName", 1))

	fmt.Println(otp.Verify("944181", 0))
}
