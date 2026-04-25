package oauthserver

import (
	"encoding/base64"
	"net"
)

// encodeNamespace converts a namespace into a reversible slash-free path
// segment.
func encodeNamespace(namespace string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(namespace))
}

func containsAll(items []string, wanted []string) bool {
	available := make(map[string]struct{}, len(items))
	for _, item := range items {
		available[item] = struct{}{}
	}

	for _, want := range wanted {
		if _, ok := available[want]; !ok {
			return false
		}
	}

	return true
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
