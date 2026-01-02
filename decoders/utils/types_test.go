package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUUIDMarshal(t *testing.T) {
	uuid := UUID{0x26, 0x5, 0x77, 0x30, 0x13, 0x29, 0x5f, 0x21,
		0xbe, 0xd7, 0xee, 0xd2, 0x7f, 0xa5, 0x8f, 0x4d}
	json, err := uuid.MarshalJSON()
	want := []byte("\"26057730-1329-5f21-bed7-eed27fa58f4d\"")
	if assert.NoError(t, err) {
		assert.Equal(t, json, want)
	}
}
