package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestJWKSAppendRejectsInvalidECKey(t *testing.T) {
	var typedNil *ecdsa.PublicKey
	for name, cert := range map[string]*x509.Certificate{
		"nil-certificate":     nil,
		"missing-key":         {},
		"typed-nil":           {PublicKey: typedNil},
		"missing-curve":       {PublicKey: &ecdsa.PublicKey{}},
		"missing-coordinates": {PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("invalid key panicked: %v", recovered)
				}
			}()
			keys := NewJWKS()
			if err := keys.Append(cert); err == nil {
				t.Fatal("invalid key appended")
			}
			if len(keys.Keys) != 0 || keys.GetLast() != nil {
				t.Fatal("invalid key published")
			}
		})
	}
}

func TestJWKSPublicKeyRejectsOffCurvePoint(t *testing.T) {
	key := &JWKSKey{KTY: "EC", CRV: "P-224", x: big.NewInt(42), y: big.NewInt(42)}
	if public := key.PublicKey(); public != nil {
		t.Fatal("off-curve coordinates produced a verification key")
	}
}
