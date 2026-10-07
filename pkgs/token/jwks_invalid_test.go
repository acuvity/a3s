package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type jwksCurveWrapper struct{ elliptic.Curve }

func TestJWKSCompatRejectsCustomCurve(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(*ecdsa.PublicKey)
	public.Curve = jwksCurveWrapper{elliptic.P256()}
	keys := NewJWKS()
	if err := keys.Append(&x509.Certificate{PublicKey: public}); !errors.Is(err, ErrJWKSInvalidKey) {
		t.Fatalf("custom curve accepted by name: %v", err)
	}
	if len(keys.Keys) != 0 {
		t.Fatal("custom curve published")
	}
}

func TestJWKSCompatMalformedPublicKeyIsUntypedNil(t *testing.T) {
	var nilKey *JWKSKey
	for name, key := range map[string]*JWKSKey{
		"nil-key":       nilKey,
		"empty":         {},
		"unknown-type":  {KTY: "RSA", CRV: "P-256", x: big.NewInt(1), y: big.NewInt(1)},
		"unknown-curve": {KTY: "EC", CRV: "unknown", x: big.NewInt(1), y: big.NewInt(1)},
		"missing-x":     {KTY: "EC", CRV: "P-256", y: big.NewInt(1)},
		"missing-y":     {KTY: "EC", CRV: "P-256", x: big.NewInt(1)},
		"negative-x":    {KTY: "EC", CRV: "P-256", x: big.NewInt(-1), y: big.NewInt(1)},
		"negative-y":    {KTY: "EC", CRV: "P-256", x: big.NewInt(1), y: big.NewInt(-1)},
		"oversized-x":   {KTY: "EC", CRV: "P-256", x: new(big.Int).Lsh(big.NewInt(1), 256), y: big.NewInt(1)},
		"oversized-y":   {KTY: "EC", CRV: "P-521", x: big.NewInt(1), y: new(big.Int).Lsh(big.NewInt(1), 521)},
		"infinity":      {KTY: "EC", CRV: "P-256", x: big.NewInt(0), y: big.NewInt(0)},
		"off-curve":     {KTY: "EC", CRV: "P-224", x: big.NewInt(42), y: big.NewInt(42)},
		"outside-field": {KTY: "EC", CRV: "P-256", x: new(big.Int).Set(elliptic.P256().Params().P), y: big.NewInt(1)},
	} {
		t.Run(name, func(t *testing.T) {
			if key.PublicKey() != nil {
				t.Fatal("malformed point produced a non-nil interface")
			}
		})
	}
}

func TestJWKSCompatInvalidRemoteMaterialCannotVerify(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "fixture"})
	token.Header["kid"] = "same-kid"
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	oversized := base64.RawURLEncoding.EncodeToString(new(big.Int).Lsh(big.NewInt(1), 256).Bytes())
	for name, key := range map[string]*JWKSKey{
		"off-curve":     {KID: "same-kid", KTY: "EC", CRV: "P-256", X: "Kg", Y: "Kg"},
		"oversized":     {KID: "same-kid", KTY: "EC", CRV: "P-256", X: oversized, Y: "AQ"},
		"missing-y":     {KID: "same-kid", KTY: "EC", CRV: "P-256", X: "AQ"},
		"unknown-curve": {KID: "same-kid", KTY: "EC", CRV: "unknown", X: "AQ", Y: "AQ"},
		"opaque-entry":  {KID: "same-kid", KTY: "RSA", X: "AQ", Y: "AQ"},
	} {
		t.Run(name, func(t *testing.T) {
			remote := jwksLoopback(t, &JWKS{Keys: []*JWKSKey{key}})
			if remote.GetLast().PublicKey() != nil {
				t.Fatal("invalid remote material produced a key")
			}
			parsed, err := jwt.Parse(signed, makeKeyFunc(remote), jwt.WithValidMethods([]string{"ES256"}))
			if err == nil || parsed.Valid {
				t.Fatal("invalid material granted verification")
			}
		})
	}
}

func TestJWKSCompatNullRemoteEntryFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{\"keys\":[null]}")) }))
	defer server.Close()
	keys, err := NewRemoteJWKS(context.Background(), server.Client(), server.URL)
	if keys != nil || !errors.Is(err, ErrJWKSInvalidKey) {
		t.Fatalf("null remote entry accepted: %v", err)
	}
}
