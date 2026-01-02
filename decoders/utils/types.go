package utils

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
)

// MacAddress is a byte slice rendered as a MAC address in JSON.
type MacAddress []byte

// MarshalJSON formats the MAC address as a JSON string.
func (s *MacAddress) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", net.HardwareAddr([]byte(*s)).String())), nil
}

// IPAddress is a byte slice rendered as an IP address in JSON.
type IPAddress []byte

// MarshalJSON formats the IP address as a JSON string.
func (s IPAddress) MarshalJSON() ([]byte, error) {
	ip, _ := netip.AddrFromSlice([]byte(s))
	return []byte(fmt.Sprintf("\"%s\"", ip.String())), nil
}

// UUID is a byte slice rendered as a UUID in JSON.
type UUID []byte

// MarshalJSON formats the UUID as a JSON string.
func (s UUID) MarshalJSON() ([]byte, error) {
	var buf [36]byte
	encodeHex(buf[:], s)
	return []byte(fmt.Sprintf("\"%s\"", string(buf[:]))), nil
}

func encodeHex(dst []byte, uuid UUID) {
	hex.Encode(dst, uuid[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])
}
