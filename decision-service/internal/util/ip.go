package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
)

// Anonymize IPv4 to /24 (IPv6 to /48), then HMAC for logs.
func HMACIP(ipStr string, key []byte) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "unknown"
	}
	var cidr string
	if v4 := ip.To4(); v4 != nil {
		cidr = v4.Mask(net.CIDRMask(24, 32)).String()
	} else {
		cidr = ip.Mask(net.CIDRMask(48, 128)).String()
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(cidr))
	return hex.EncodeToString(m.Sum(nil))[:16]
}
