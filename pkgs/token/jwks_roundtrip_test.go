package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type jwksPointVector struct{ Curve, Scalar, X, Y string }

func jwksPointVectors(t *testing.T) []jwksPointVector {
	t.Helper()
	data, err := os.ReadFile("testdata/jwks_points.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []jwksPointVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func jwksFixturePrivate(t *testing.T, vector jwksPointVector) *ecdsa.PrivateKey {
	t.Helper()
	scalar, err := hex.DecodeString(vector.Scalar)
	if err != nil {
		t.Fatal(err)
	}
	curve := (&JWKSKey{CRV: vector.Curve}).Curve()
	private, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func jwksLoopback(t *testing.T, keys *JWKS) *JWKS {
	t.Helper()
	data, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) }))
	t.Cleanup(server.Close)
	remote, err := NewRemoteJWKS(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return remote
}

// Golden wire coordinates were captured from the original minimal-width X/Y
// encoding for fixed, public test scalars. They include leading-zero X and Y
// points for every supported curve; no live key material is used.
func TestJWKSCompatHistoricalWireAndSignatures(t *testing.T) {
	for _, vector := range jwksPointVectors(t) {
		t.Run(vector.Curve+"/"+vector.Scalar, func(t *testing.T) {
			private := jwksFixturePrivate(t, vector)
			cert := &x509.Certificate{Raw: []byte("public test fixture " + vector.Curve + vector.Scalar), PublicKey: private.Public()}
			keys := NewJWKS()
			if err := keys.AppendWithPrivate(cert, private); err != nil {
				t.Fatal(err)
			}
			key := keys.GetLast()
			if key.KID != Fingerprint(cert) || key.CRV != vector.Curve || key.KTY != "EC" || key.Use != "sig" || key.X != vector.X || key.Y != vector.Y || key.PrivateKey() != private {
				t.Fatalf("historical wire identity changed: %+v", key)
			}
			hash := sha256.Sum256([]byte("jwks round-trip fixture"))
			signature, err := ecdsa.SignASN1(rand.Reader, private, hash[:])
			if err != nil {
				t.Fatal(err)
			}
			other, err := ecdsa.GenerateKey(private.Curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			wrongSignature, err := ecdsa.SignASN1(rand.Reader, other, hash[:])
			if err != nil {
				t.Fatal(err)
			}
			for _, padded := range []bool{false, true} {
				wireKey := *key
				if padded {
					size := (private.Curve.Params().BitSize + 7) / 8
					for _, coord := range []*string{&wireKey.X, &wireKey.Y} {
						raw, err := base64.RawURLEncoding.DecodeString(*coord)
						if err != nil {
							t.Fatal(err)
						}
						raw = append(make([]byte, size-len(raw)), raw...)
						*coord = base64.RawURLEncoding.EncodeToString(raw)
					}
				}
				remote := jwksLoopback(t, &JWKS{Keys: []*JWKSKey{&wireKey}})
				actual, err := remote.Get(key.KID)
				if err != nil {
					t.Fatal(err)
				}
				public, ok := actual.PublicKey().(*ecdsa.PublicKey)
				if !ok || !public.Equal(private.Public()) || !ecdsa.VerifyASN1(public, hash[:], signature) {
					t.Fatalf("signature failed; padded=%v", padded)
				}
				if ecdsa.VerifyASN1(public, hash[:], wrongSignature) {
					t.Fatal("another key verified under the same KID")
				}
				if vector.Curve != "P-224" {
					method := map[string]*jwt.SigningMethodECDSA{"P-256": jwt.SigningMethodES256, "P-384": jwt.SigningMethodES384, "P-521": jwt.SigningMethodES512}[vector.Curve]
					token := jwt.NewWithClaims(method, jwt.MapClaims{"sub": "fixture"})
					token.Header["kid"] = key.KID
					signed, err := token.SignedString(private)
					if err != nil {
						t.Fatal(err)
					}
					verified, err := jwt.Parse(signed, makeKeyFunc(remote), jwt.WithValidMethods([]string{method.Alg()}))
					if err != nil || !verified.Valid {
						t.Fatalf("native key lookup rejected valid JWT: %v", err)
					}
					wrong, err := token.SignedString(other)
					if err != nil {
						t.Fatal(err)
					}
					if result, err := jwt.Parse(wrong, makeKeyFunc(remote), jwt.WithValidMethods([]string{method.Alg()})); err == nil || result.Valid {
						t.Fatal("wrong signature verified with the real KID")
					}
				}
			}
		})
	}
}

func TestJWKSCompatConcurrentLookup(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := NewJWKS()
	if err := keys.Append(&x509.Certificate{Raw: []byte("concurrent fixture"), PublicKey: private.Public()}); err != nil {
		t.Fatal(err)
	}
	remote := jwksLoopback(t, keys)
	key := remote.GetLast()
	start := make(chan struct{})
	failures := make(chan error, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 32 {
				public, ok := key.PublicKey().(*ecdsa.PublicKey)
				if !ok || !public.Equal(private.Public()) {
					failures <- fmt.Errorf("concurrent lookup changed public key")
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestJWKSCompatAppendDetachesCallerKey(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("owned fixture"))
	signature, err := ecdsa.SignASN1(rand.Reader, private, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	original := private.Public().(*ecdsa.PublicKey)
	keys := NewJWKS()
	if err := keys.Append(&x509.Certificate{Raw: []byte("ownership fixture"), PublicKey: original}); err != nil {
		t.Fatal(err)
	}
	// Replacing the caller's original key must not mutate the published key.
	*original = ecdsa.PublicKey{}
	public, ok := keys.GetLast().PublicKey().(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(public, hash[:], signature) {
		t.Fatal("caller mutation invalidated owned verification key")
	}
}
