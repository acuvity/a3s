// Package oauth holds the OAuth authorization server logic of a3s that is
// needed without depending on the server.
package oauth

import (
	"encoding/base64"
	"net/url"
	"strings"
)

// encodeNamespace converts a namespace into a reversible slash-free path
// segment.
func encodeNamespace(namespace string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(namespace))
}

// IssuerFor returns the issuer of the OAuth authorization server of a3s for a
// namespace: <a3s issuer>/oauth/<encoded namespace>, or <a3s issuer>/oauth for
// the root namespace.
func IssuerFor(a3sIssuer string, namespace string) (string, error) {

	u, err := url.Parse(a3sIssuer)
	if err != nil {
		return "", err
	}

	u.Path += "/oauth"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""

	if namespace == "/" {
		return u.String(), nil
	}

	return u.String() + "/" + encodeNamespace(namespace), nil
}

// A3SIssuer returns the a3s issuer that IssuerFor derived issuer from for
// namespace. It returns false if issuer is not an OAuth issuer of namespace.
func A3SIssuer(issuer string, namespace string) (string, bool) {

	suffix := "/oauth"
	if namespace != "/" {
		suffix += "/" + encodeNamespace(namespace)
	}

	return strings.CutSuffix(issuer, suffix)
}
