package gotp

import (
	"errors"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
)

var defaultTestSecret = []byte("12345678901234567890")

func TestOTP_InvalidLength(t *testing.T) {
	_, err := newOTP(defaultTestSecret, WithLength(9))
	assert.Error(t, err)
	_, err = newOTP(defaultTestSecret, WithLength(-1))
	assert.Error(t, err)
}

func TestOTP_InvalidInterval(t *testing.T) {
	_, err := newOTP(defaultTestSecret, WithInterval(-1))
	assert.Error(t, err)
}

type brokenHash struct{}

func (*brokenHash) Sum(b []byte) []byte               { return []byte{} }
func (*brokenHash) Reset()                            {}
func (*brokenHash) Size() int                         { return 0 }
func (*brokenHash) BlockSize() int                    { return 0 }
func (*brokenHash) Write(p []byte) (n int, err error) { return 0, errors.New("fake") }
func NewHash() hash.Hash                              { return new(brokenHash) }

func TestOTP_GenerateError(t *testing.T) {
	brokenHasher := &Hasher{HashName: "broken", Digest: NewHash}
	otp, err := newOTP(defaultTestSecret, WithHasher(brokenHasher))
	assert.NoError(t, err)

	_, err = otp.generateOTP(0)
	assert.Error(t, err)
}
