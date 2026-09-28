package oauthserver

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
)

// encodeNamespace converts a namespace into a reversible slash-free path
// segment.
func encodeNamespace(namespace string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(namespace))
}

// decodeNamespace converts an encoded namespace path segment into its
// namespace form.
func decodeNamespace(encoded string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode namespace: %w", err)
	}

	namespace := string(raw)
	if err := validateNamespace(namespace); err != nil {
		return "", err
	}

	return namespace, nil
}

func validateNamespace(namespace string) error {
	if namespace == "" {
		return errors.New("missing namespace")
	}

	if !strings.HasPrefix(namespace, "/") {
		return fmt.Errorf("invalid namespace %q", namespace)
	}

	if namespace != "/" && strings.HasSuffix(namespace, "/") {
		return fmt.Errorf("invalid namespace %q", namespace)
	}

	if strings.Contains(namespace, "//") {
		return fmt.Errorf("invalid namespace %q", namespace)
	}

	return nil
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

// SourceAllowed reports whether the oauth application admits the given
// source through its allowedSources filters. An application without filters
// admits any source.
func SourceAllowed(app *api.OAuthApplication, source elemental.AttributeSpecifiable) (bool, error) {
	for _, allowed := range app.AllowedSources {
		filter, err := elemental.NewFilterFromString(allowed)
		if err != nil {
			return false, fmt.Errorf("invalid allowedSources filter %q on oauth application %q: %w", allowed, app.Name, err)
		}

		matched, err := elemental.MatchesFilter(source, filter)
		if err != nil {
			return false, fmt.Errorf("unable to evaluate allowedSources filter %q on oauth application %q: %w", allowed, app.Name, err)
		}
		if matched {
			return true, nil
		}
	}

	return len(app.AllowedSources) == 0, nil
}
