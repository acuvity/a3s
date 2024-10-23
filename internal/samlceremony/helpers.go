package samlceremony

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"go.acuvity.ai/bahamut"
)

// GenerateNonce generate a nonce.
func GenerateNonce(nonceSourceSize int) (string, error) {

	nonceSource := make([]byte, nonceSourceSize)
	_, err := rand.Read(nonceSource)
	if err != nil {
		return "", err
	}
	sha := sha256.Sum256(nonceSource) // #nosec

	return base64.RawStdEncoding.EncodeToString(sha[:]), nil
}

// MakeRedirectError will configure will return a decorator function that can be
// used to handler errors. If the url is not empty, the request will be redirected
// to that URL with error set in the 'error=' query parameter. Otherwise it will just
// return the err as usual.
func MakeRedirectError(ctx bahamut.Context, url string) func(err error) error {

	return func(err error) error {
		if url == "" {
			return fmt.Errorf("unable to redirect saml error. empty url")
		}

		d, e := json.Marshal(err)
		if e != nil {
			return fmt.Errorf("unable to decode saml error for redirection: %w", err)
		}

		ctx.SetRedirect(fmt.Sprintf("%s?error=%s", url, string(d)))

		return nil
	}
}
