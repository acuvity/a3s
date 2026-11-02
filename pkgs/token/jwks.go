package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"go.acuvity.ai/elemental"
)

// Various errors returned by a JWKS.
var (
	ErrJWKSNotFound    = errors.New("kid not found in JWKS")
	ErrJWKSInvalidType = errors.New("certificate must be ecdsa")
	ErrJWKSInvalidKey  = errors.New("invalid ecdsa public key")
	ErrJWKSKeyExists   = errors.New("key with the same kid already exists")
	mTry               = 20
)

// A ErrJWKSRemote represents an error while
// interacting with a remote JWKS.
type ErrJWKSRemote struct {
	Err error
}

func (e ErrJWKSRemote) Error() string {
	return fmt.Sprintf("remote jwks error: %s", e.Err)
}

// Unwrap returns the warped error.
func (e ErrJWKSRemote) Unwrap() error {
	return e.Err
}

// A JWKS is a structure to manage a JSON Web Key Set.
type JWKS struct {
	Keys []*JWKSKey `json:"keys"`

	keyMap map[string]*JWKSKey

	sync.RWMutex
}

// NewJWKS returns a new JWKS.
func NewJWKS() *JWKS {
	return &JWKS{
		keyMap: map[string]*JWKSKey{},
	}
}

// NewRemoteJWKS returns a JWKS prepulated with the
// data found at the given URL using the provided http.Client.
// If http.Client is nil, the default client will be used.
func NewRemoteJWKS(ctx context.Context, client *http.Client, url string) (*JWKS, error) {

	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ErrJWKSRemote{Err: fmt.Errorf("unable to build request: %w", err)}
	}

	var resp *http.Response
	for i := 0; i < mTry; i++ {

		if resp, err = client.Do(req); err != nil {
			err = ErrJWKSRemote{Err: fmt.Errorf("unable to send request: %w", err)}
			slog.Warn("Unable to access JWKS. Retrying", "try", i+1, "max", mTry, err)
			time.Sleep(3 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			err = ErrJWKSRemote{Err: fmt.Errorf("invalid status code: %s", resp.Status)}
			slog.Warn("Unable to access JWKS. Retrying", "try", i+1, "max", mTry, err)
			time.Sleep(3 * time.Second)
			continue
		}

		defer resp.Body.Close() // nolint
		break
	}

	if err != nil {
		return nil, err
	}

	jwks := NewJWKS()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrJWKSRemote{Err: fmt.Errorf("unable to read response body: %w", err)}
	}

	if err := elemental.Decode(elemental.EncodingTypeJSON, data, jwks); err != nil {
		return nil, ErrJWKSRemote{Err: fmt.Errorf("unable to parse response body: %w", err)}
	}

	for _, k := range jwks.Keys {

		if k == nil {
			return nil, ErrJWKSRemote{Err: ErrJWKSInvalidKey}
		}
		jwks.keyMap[k.KID] = k

		if k.X != "" && k.Y != "" {

			x, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil {
				return nil, ErrJWKSRemote{Err: fmt.Errorf("unable to decode X: %w", err)}
			}
			k.x = &big.Int{}
			k.x.SetBytes(x)

			y, err := base64.RawURLEncoding.DecodeString(k.Y)
			if err != nil {
				return nil, ErrJWKSRemote{Err: fmt.Errorf("unable to decode Y: %w", err)}
			}
			k.y = &big.Int{}
			k.y.SetBytes(y)
		}
		// Prepare before publishing the set: concurrent verification is read-only.
		// Unknown/invalid entries remain loadable but cannot provide an EC key.
		k.public = k.parsePublicKey()
	}

	return jwks, nil
}

// Append appends a new certificate to the JWKS.
func (j *JWKS) Append(cert *x509.Certificate) error {
	return j.AppendWithPrivate(cert, nil)
}

// AppendWithPrivate appends a new certificate and its private key to the JWKS.
func (j *JWKS) AppendWithPrivate(cert *x509.Certificate, private crypto.PrivateKey) error {

	j.Lock()
	defer j.Unlock()

	if cert == nil {
		return ErrJWKSInvalidType
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || public == nil {
		return ErrJWKSInvalidType
	}

	kid := Fingerprint(cert)

	if _, ok := j.keyMap[kid]; ok {
		return ErrJWKSKeyExists
	}

	point, err := encodeECDSAPublicKey(public)
	if err != nil {
		return err
	}
	size := (len(point) - 1) / 2
	x := new(big.Int).SetBytes(point[1 : 1+size])
	y := new(big.Int).SetBytes(point[1+size:])
	k := &JWKSKey{
		KTY: "EC",
		KID: kid,
		Use: "sig",
		CRV: public.Curve.Params().Name,
		// Preserve the existing minimal-width JWK encoding, not SEC 1 padding.
		X:       base64.RawURLEncoding.EncodeToString(x.Bytes()),
		x:       x,
		Y:       base64.RawURLEncoding.EncodeToString(y.Bytes()),
		y:       y,
		private: private,
	}
	k.public = k.parsePublicKey()
	if k.public == nil {
		return ErrJWKSInvalidKey
	}

	j.Keys = append(j.Keys, k)
	j.keyMap[kid] = k

	return nil
}

// encodeECDSAPublicKey contains only the standard-library encoding call. Go 1.26
// Bytes reports malformed points as errors but panics on nil affine coordinates;
// a malformed caller-supplied certificate must fail closed instead of panicking.
func encodeECDSAPublicKey(public *ecdsa.PublicKey) (point []byte, err error) {
	defer func() {
		if recover() != nil {
			point, err = nil, ErrJWKSInvalidKey
		}
	}()
	point, err = public.Bytes()
	if err != nil {
		return nil, ErrJWKSInvalidKey
	}
	return point, nil
}

// Get returns the key with the given ID.
// Returns ErrJWKSNotFound if not found.
func (j *JWKS) Get(kid string) (*JWKSKey, error) {

	j.RLock()
	defer j.RUnlock()

	k, ok := j.keyMap[kid]
	if !ok {
		return nil, ErrJWKSNotFound
	}

	return k, nil
}

// GetLast returns the last inserted key.
func (j *JWKS) GetLast() *JWKSKey {

	j.RLock()
	defer j.RUnlock()

	if len(j.Keys) == 0 {
		return nil
	}

	return j.Keys[len(j.Keys)-1]
}

// GetLastWithPrivate returns the last inserted key that contains a private key.
func (j *JWKS) GetLastWithPrivate() *JWKSKey {

	j.RLock()
	defer j.RUnlock()

	if len(j.Keys) == 0 {
		return nil
	}

	for i := len(j.Keys) - 1; i >= 0; i-- {
		if k := j.Keys[i]; k.private != nil {
			return k
		}
	}

	return nil
}

// Del deletes the key with the given ID.
// Returns true if something was deleted, false
// otherwise.
func (j *JWKS) Del(kid string) bool {

	j.Lock()
	defer j.Unlock()

	if _, ok := j.keyMap[kid]; !ok {
		return false
	}

	delete(j.keyMap, kid)

	var idx int
	for i, key := range j.Keys {
		if key.KID == kid {
			idx = i
			break
		}
	}

	j.Keys = append(j.Keys[:idx], j.Keys[idx+1:]...)

	return true
}

// JWKSKey represents a single key stored in a JWKS. Keys and returned public
// keys are shared read-only values after publication; callers must not mutate them.
type JWKSKey struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	CRV string `json:"crv,omitempty"`

	x       *big.Int
	y       *big.Int
	private crypto.PrivateKey
	public  crypto.PublicKey
}

// Curve returns the curve used by the key.
func (k *JWKSKey) Curve() elliptic.Curve {

	switch k.CRV {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

// PublicKey returns a ready to use crypto.PublicKey, or nil for an invalid key.
// Preparation finishes before publication; reads never populate a cache.
func (k *JWKSKey) PublicKey() crypto.PublicKey {

	if k == nil {
		return nil
	}
	if k.public != nil {
		return k.public
	}
	return k.parsePublicKey()
}

func (k *JWKSKey) parsePublicKey() crypto.PublicKey {
	curve := k.Curve()
	if k.KTY != "EC" || curve == nil || k.x == nil || k.y == nil || k.x.Sign() < 0 || k.y.Sign() < 0 {
		return nil
	}
	bits := curve.Params().BitSize
	if k.x.BitLen() > bits || k.y.BitLen() > bits {
		return nil
	}
	size := (bits + 7) / 8
	point := make([]byte, 1+2*size)
	point[0] = 4 // SEC 1 uncompressed point; coordinates are fixed-width here.
	k.x.FillBytes(point[1 : 1+size])
	k.y.FillBytes(point[1+size:])
	public, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil
	}
	return public
}

// PrivateKey returns the crypto.PrivateKey associated to
// the public key, if it was given it was added to the JWKS.
func (k *JWKSKey) PrivateKey() crypto.PrivateKey {
	return k.private
}
