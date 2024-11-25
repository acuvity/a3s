package oauth2ceremony

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

	return base64.StdEncoding.EncodeToString(sha[:]), nil
}

// MakeClient returns a OIDC client using the given CA.
func MakeClient(ca string) (*http.Client, error) {

	var pool *x509.CertPool
	var err error

	if ca != "" {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			return nil, fmt.Errorf("unable to append given ca to ca pool")
		}
	} else {
		pool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("unable to initialize system root ca pool: %w", err)
		}
	}

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}, nil
}

// MakeRedirectError will configure will return a decorator function that can be
// used to handler errors. If the url is not empty, the request will be redirected
// to that URL with error set in the 'error=' query parameter. Otherwise it will just
// return the err as usual.
func MakeRedirectError(ctx bahamut.Context, url string) func(err error) error {

	return func(err error) error {

		if url == "" {
			return err
		}

		d, e := json.Marshal(err)
		if e != nil {
			return err
		}

		ctx.SetRedirect(fmt.Sprintf("%s?error=%s", url, string(d)))

		return nil
	}
}
