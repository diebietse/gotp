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
	otp, err := gotp.NewDefaultTOTP("4S62BZNFXXSZLCRO")
	if err != nil {
		panic(err)
	}

	fmt.Println("current one-time password is:", otp.Now())
	fmt.Println("one-time password of timestamp 0 is:", otp.At(0))
	fmt.Println(otp.ProvisioningURI("demoAccountName", "issuerName"))

	fmt.Println(otp.Verify("179394", 1524485781))
}

func defaultHOTPUsage() {
	otp, err := gotp.NewDefaultHOTP("4S62BZNFXXSZLCRO")
	if err != nil {
		panic(err)
	}

	fmt.Println("one-time password of counter 0 is:", otp.At(0))
	fmt.Println(otp.ProvisioningURI("demoAccountName", "issuerName", 1))

	fmt.Println(otp.Verify("944181", 0))
}
