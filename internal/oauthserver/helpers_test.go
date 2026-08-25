package oauthserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

func newOAuthHTTPHandlerForTest(t *testing.T) *HTTPHandler {
	t.Helper()

	baseURL := "https://issuer.example"
	oauth, _ := NewOAuth(nil, &fakeManipulator{}, token.NewJWKS(), baseURL, testA3SAudience, 5*time.Minute)

	return NewHTTPHandler(oauth, "")
}

func assertOAuthJSONField(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int, field string, want any) {
	t.Helper()

	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d", recorder.Code, wantStatus)
	}

	payload := map[string]any{}
	if err := jsonNewDecoder(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}

	got, ok := payload[field]
	if !ok {
		t.Fatalf("response missing field %q", field)
	}

	if !oauthJSONEqual(got, want) {
		t.Fatalf("%s = %#v, want %#v", field, got, want)
	}
}

func oauthJSONEqual(got any, want any) bool {
	switch wanted := want.(type) {
	case []any:
		gotSlice, ok := got.([]any)
		if !ok || len(gotSlice) != len(wanted) {
			return false
		}
		for i := range wanted {
			if gotSlice[i] != wanted[i] {
				return false
			}
		}
		return true
	default:
		return got == want
	}
}

func withDisabled(app *api.OAuthApplication, disabled bool) *api.OAuthApplication {
	copyApp := *app
	copyApp.Disabled = disabled
	return &copyApp
}

func jsonNewDecoder(data []byte, dest any) error {
	return json.Unmarshal(data, dest)
}

type fakeManipulator struct {
	client *api.OAuthClient
	app    *api.OAuthApplication
}

func (f *fakeManipulator) RetrieveMany(_ manipulate.Context, dest elemental.Identifiables) error {
	clients, ok := dest.(*api.OAuthClientsList)
	if !ok {
		return errors.New("unexpected RetrieveMany destination")
	}

	if f.client == nil {
		*clients = nil
		return nil
	}

	copyClient := *f.client
	*clients = api.OAuthClientsList{&copyClient}
	return nil
}

func (f *fakeManipulator) Retrieve(_ manipulate.Context, object elemental.Identifiable) error {
	app, ok := object.(*api.OAuthApplication)
	if !ok {
		return errors.New("unexpected Retrieve destination")
	}

	if f.app == nil {
		return manipulate.ErrObjectNotFound{Err: errors.New("oauth application not found")}
	}
	if app.Identifier() != "" && f.app.Identifier() != "" && app.Identifier() != f.app.Identifier() {
		return manipulate.ErrObjectNotFound{Err: errors.New("oauth application not found")}
	}

	*app = *f.app
	return nil
}

func (*fakeManipulator) Create(manipulate.Context, elemental.Identifiable) error {
	return errors.New("not implemented")
}

func (*fakeManipulator) Update(manipulate.Context, elemental.Identifiable) error {
	return errors.New("not implemented")
}

func (*fakeManipulator) Delete(manipulate.Context, elemental.Identifiable) error {
	return errors.New("not implemented")
}

func (*fakeManipulator) DeleteMany(manipulate.Context, elemental.Identity) error {
	return errors.New("not implemented")
}

func (*fakeManipulator) Count(manipulate.Context, elemental.Identity) (int, error) {
	return 0, errors.New("not implemented")
}

func makeTestECCert(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "oauthserver-test",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	return cert, key
}
