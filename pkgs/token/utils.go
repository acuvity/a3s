package token

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

// FromRequest retrieves the token from the given elemental.Request
// first looking at the request.Password then the cookie x-a3s-token.
func FromRequest(req *elemental.Request) string {

	if req.Password != "" {
		return req.Password
	}

	if hreq := req.HTTPRequest(); hreq != nil {
		if cookie, err := hreq.Cookie("x-a3s-token"); err == nil {
			return cookie.Value
		}
	}

	return ""
}

// FromHTTPRequest retrieves the token from the given elemental.Request
// first looking at the Authorization header then the cookie x-a3s-token.
func FromHTTPRequest(req *http.Request) string {

	if authstring := req.Header.Get("Authorization"); authstring != "" {
		parts := strings.SplitN(authstring, "Bearer ", 2)
		if len(parts) < 2 {
			return ""
		}

		if parts[1] != "" {
			return parts[1]
		}
	}

	if cookie, err := req.Cookie("x-a3s-token"); err == nil {
		return cookie.Value
	}

	return ""
}

// FromSession retrieves the token from the given bahamut.Session
// first looking at the session.Token(), then the cookie x-a3s-token.
func FromSession(session bahamut.Session) string {

	if t := session.Token(); t != "" {
		return t
	}

	if cookie, err := session.Cookie("x-a3s-token"); err == nil {
		return cookie.Value
	}

	return ""
}

// Fingerprint returns the fingerprint of the given certificate.
func Fingerprint(cert *x509.Certificate) string {

	return fmt.Sprintf("%02X", sha256.Sum256(cert.Raw)) // #nosec
}

// JWKSFromTokenIssuer will retrieve a remote JWKS from the issuer field
// in the given idt, using the eventually given tlsConfig to retrieve the JWKS..
// You usually want to pass a non verified IdentityToken here (from ParseUnverified for instance)
// so you can then correctly verify it using Parse().
func JWKSFromTokenIssuer(ctx context.Context, idt *IdentityToken, tlsConfig *tls.Config) (*JWKS, error) {

	wellKnownSuffix := ".well-known/jwks.json"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	endpoint := idt.Issuer
	if !strings.HasSuffix(endpoint, wellKnownSuffix) {
		if discovered, err := oauthJWKSURL(ctx, endpoint, client); err == nil {
			endpoint = discovered
		} else {
			u, err := url.Parse(endpoint)
			if err != nil {
				return nil, fmt.Errorf("unable to parse issuer url: %w", err)
			}
			u.Path = wellKnownSuffix
			endpoint = u.String()
		}
	}

	jwks, err := NewRemoteJWKS(ctx, client, endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve remote jwks: %w", err)
	}

	return jwks, nil
}

func oauthJWKSURL(ctx context.Context, issuer string, client *http.Client) (string, error) {

	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}

	u.Path = "/.well-known/oauth-authorization-server" + u.EscapedPath()
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() // nolint

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid status code: %s", resp.Status)
	}

	var metadata struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return "", err
	}
	if metadata.Issuer != issuer {
		return "", fmt.Errorf("invalid issuer %q", metadata.Issuer)
	}
	if metadata.JWKSURI == "" {
		return "", fmt.Errorf("missing jwks_uri")
	}

	return metadata.JWKSURI, nil
}

func makeKeyFunc(keychain *JWKS) jwt.Keyfunc {

	return func(token *jwt.Token) (any, error) {

		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token has no KID in its header")
		}

		k, err := keychain.Get(kid)
		if err != nil {
			return nil, fmt.Errorf("unable to find kid '%s': %w", kid, err)
		}

		return k.PublicKey(), nil
	}
}
