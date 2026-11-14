package entraissuer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/tg/tglib"
)

const (
	testTenantID    = "1ec8ce6a-2b6d-4828-b298-be4d2eeb573b"
	testAPIAppID    = "d0592634-6147-4f2f-9c29-112a88633d0d"
	testNativeAppID = "151996fb-07f3-47d9-b180-cc057bcedf72"
	testScope       = "acme.exchange"
	testOID         = "36ce5c92-16da-455d-afa0-259d3c610f2b"
	testKID         = "test-key"
)

// fakeEntra is an Entra login endpoint publishing the signing key of a
// single tenant.
type fakeEntra struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newFakeEntra(t *testing.T, tenantID string) *fakeEntra {

	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate key: %s", err)
	}

	jwks, err := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": testKID,
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("unable to encode jwks: %s", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/"+tenantID+"/discovery/v2.0/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &fakeEntra{
		server: server,
		key:    key,
	}
}

func (f *fakeEntra) config() Config {

	return Config{
		LoginURL:     f.server.URL,
		APIAppID:     testAPIAppID,
		NativeAppIDs: []string{testNativeAppID},
		Scope:        testScope,
	}
}

func (f *fakeEntra) issuer(tenantID string) string {
	return fmt.Sprintf("%s/%s/v2.0", f.server.URL, tenantID)
}

// claims returns the claims of a valid access token issued by the tenant.
func (f *fakeEntra) claims() jwt.MapClaims {

	now := time.Now()

	return jwt.MapClaims{
		"iss":                f.issuer(testTenantID),
		"aud":                testAPIAppID,
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"ver":                "2.0",
		"tid":                testTenantID,
		"azp":                testNativeAppID,
		"scp":                testScope,
		"oid":                testOID,
		"upn":                "joe@acme.onmicrosoft.com",
		"preferred_username": "joe@acme.onmicrosoft.com",
		"name":               "Joe",
		"email":              "joe@acme.com",
		"groups":             []string{"g1", "g2"},
	}
}

func (f *fakeEntra) sign(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {

	t.Helper()

	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tkn.Header["kid"] = testKID

	s, err := tkn.SignedString(key)
	if err != nil {
		t.Fatalf("unable to sign token: %s", err)
	}

	return s
}

// makeTestModifier returns a source modifier calling server with a client
// certificate.
func makeTestModifier(t *testing.T, server *httptest.Server) *api.IdentityModifier {

	t.Helper()

	certBlock, keyBlock, err := tglib.Issue(pkix.Name{})
	if err != nil {
		t.Fatalf("unable to issue certificate: %s", err)
	}

	caBlock, err := tglib.CertToPEM(server.Certificate())
	if err != nil {
		t.Fatalf("unable to encode certificate: %s", err)
	}

	return &api.IdentityModifier{
		CA:          string(pem.EncodeToMemory(caBlock)),
		URL:         server.URL,
		Certificate: string(pem.EncodeToMemory(certBlock)),
		Key:         string(pem.EncodeToMemory(keyBlock)),
		Method:      api.IdentityModifierMethodPOST,
	}
}

func makeTestSource() *api.EntraSource {

	src := api.NewEntraSource()
	src.Namespace = "/ns"
	src.Name = "corp"
	src.TenantID = testTenantID

	return src
}

func TestErrEntra(t *testing.T) {
	Convey("ErrEntra should behave correctly", t, func() {
		e := fmt.Errorf("boom")
		err := ErrEntra{Err: e}
		So(err.Error(), ShouldEqual, "entra error: boom")
		So(err.Unwrap(), ShouldEqual, e)
	})
}

func TestConfig_IsEnabled(t *testing.T) {

	full := Config{
		LoginURL:     "https://login.microsoftonline.com",
		APIAppID:     testAPIAppID,
		NativeAppIDs: []string{testNativeAppID},
		Scope:        testScope,
	}

	Convey("Given a config with every setting", t, func() {
		So(full.IsEnabled(), ShouldBeTrue)
	})

	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"without login URL", func(c *Config) { c.LoginURL = "" }},
		{"without API app ID", func(c *Config) { c.APIAppID = "" }},
		{"without native app IDs", func(c *Config) { c.NativeAppIDs = nil }},
		{"without scope", func(c *Config) { c.Scope = "" }},
	}

	for _, tt := range tests {
		Convey("Given a config "+tt.name, t, func() {
			cfg := full
			tt.modify(&cfg)
			So(cfg.IsEnabled(), ShouldBeFalse)
		})
	}
}

func TestNew(t *testing.T) {

	entra := newFakeEntra(t, testTenantID)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate key: %s", err)
	}

	Convey("Given a valid token", t, func() {

		iss, err := New(context.Background(), makeTestSource(), entra.sign(t, entra.key, entra.claims()), entra.config(), nil)

		So(err, ShouldBeNil)
		So(iss.Issue().Source.Type, ShouldEqual, "entra")
		So(iss.Issue().Source.Namespace, ShouldEqual, "/ns")
		So(iss.Issue().Source.Name, ShouldEqual, "corp")
		So(iss.Issue().Identity, ShouldResemble, []string{
			"tenantid=" + testTenantID,
			"oid=" + testOID,
			"name=joe@acme.onmicrosoft.com",
			"displayname=Joe",
			"email=joe@acme.com",
			"group:id=g1",
			"group:id=g2",
		})
	})

	Convey("Given a valid token without upn", t, func() {

		claims := entra.claims()
		delete(claims, "upn")

		iss, err := New(context.Background(), makeTestSource(), entra.sign(t, entra.key, claims), entra.config(), nil)

		So(err, ShouldBeNil)
		So(iss.Issue().Identity, ShouldResemble, []string{
			"tenantid=" + testTenantID,
			"oid=" + testOID,
			"displayname=Joe",
			"email=joe@acme.com",
			"group:id=g1",
			"group:id=g2",
		})
	})

	Convey("Given a valid token with only the mandatory claims", t, func() {

		claims := entra.claims()
		for _, k := range []string{"upn", "preferred_username", "name", "email", "groups"} {
			delete(claims, k)
		}

		iss, err := New(context.Background(), makeTestSource(), entra.sign(t, entra.key, claims), entra.config(), nil)

		So(err, ShouldBeNil)
		So(iss.Issue().Identity, ShouldResemble, []string{
			"tenantid=" + testTenantID,
			"oid=" + testOID,
		})
	})

	Convey("Given a login URL with a trailing slash", t, func() {

		cfg := entra.config()
		cfg.LoginURL += "/"

		_, err := New(context.Background(), makeTestSource(), entra.sign(t, entra.key, entra.claims()), cfg, nil)

		So(err, ShouldBeNil)
	})

	Convey("Given a source configured with an uppercase tenant ID", t, func() {

		src := makeTestSource()
		src.TenantID = "1EC8CE6A-2B6D-4828-B298-BE4D2EEB573B"

		_, err := New(context.Background(), src, entra.sign(t, entra.key, entra.claims()), entra.config(), nil)

		So(err, ShouldBeNil)
	})

	Convey("Given a source whose tenant publishes no keys", t, func() {

		const otherTenantID = "00000000-0000-0000-0000-000000000000"

		src := makeTestSource()
		src.TenantID = otherTenantID

		claims := entra.claims()
		claims["iss"] = entra.issuer(otherTenantID)
		claims["tid"] = otherTenantID

		_, err := New(context.Background(), src, entra.sign(t, entra.key, claims), entra.config(), nil)

		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "unable to verify token")
	})

	Convey("Given a token signed by another key", t, func() {

		_, err := New(context.Background(), makeTestSource(), entra.sign(t, otherKey, entra.claims()), entra.config(), nil)

		So(err, ShouldNotBeNil)
		So(errors.As(err, &ErrEntra{}), ShouldBeTrue)
		So(err.Error(), ShouldContainSubstring, "unable to verify token")
	})

	Convey("Given an invalid token", t, func() {

		_, err := New(context.Background(), makeTestSource(), "not a token", entra.config(), nil)

		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "unable to verify token")
	})

	checker, err := netsafe.MakeChecker([]string{"11.0.0.1/32"}, nil)
	if err != nil {
		t.Fatalf("unable to make checker: %s", err)
	}
	rm := netsafe.NewRequestMaker(checker)

	Convey("Given a source with a modifier", t, func() {

		modifier := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte(`["team=blue"]`))
		}))
		defer modifier.Close()

		src := makeTestSource()
		src.Modifier = makeTestModifier(t, modifier)

		iss, err := New(context.Background(), src, entra.sign(t, entra.key, entra.claims()), entra.config(), rm)

		So(err, ShouldBeNil)
		So(iss.Issue().Identity, ShouldResemble, []string{"team=blue"})
	})

	Convey("Given a source with a failing modifier", t, func() {

		modifier := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer modifier.Close()

		src := makeTestSource()
		src.Modifier = makeTestModifier(t, modifier)

		_, err := New(context.Background(), src, entra.sign(t, entra.key, entra.claims()), entra.config(), rm)

		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "unable to call modifier")
	})

	Convey("Given a source with an invalid modifier", t, func() {

		src := makeTestSource()
		src.Modifier = &api.IdentityModifier{URL: "https://modifier.example.com", Method: api.IdentityModifierMethodPOST}

		_, err := New(context.Background(), src, entra.sign(t, entra.key, entra.claims()), entra.config(), rm)

		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "unable to prepare source modifier")
	})

	tests := []struct {
		name   string
		modify func(jwt.MapClaims)
		want   string
	}{
		{
			"issued by another tenant",
			func(c jwt.MapClaims) {
				c["iss"] = entra.issuer("00000000-0000-0000-0000-000000000000")
				c["tid"] = "00000000-0000-0000-0000-000000000000"
			},
			"id token issued by a different provider",
		},
		{
			"with a tid not matching the issuer",
			func(c jwt.MapClaims) { c["tid"] = "00000000-0000-0000-0000-000000000000" },
			"unexpected tenant",
		},
		{
			"for another audience",
			func(c jwt.MapClaims) { c["aud"] = "00000003-0000-0000-c000-000000000000" },
			"expected audience",
		},
		{
			"obtained by another application",
			func(c jwt.MapClaims) { c["azp"] = "00000000-0000-0000-0000-000000000000" },
			"unexpected authorized party",
		},
		{
			"without the exchange scope",
			func(c jwt.MapClaims) { c["scp"] = "User.Read" },
			"missing scope",
		},
		{
			"with the exchange scope among others",
			func(c jwt.MapClaims) { c["scp"] = "User.Read " + testScope },
			"",
		},
		{
			"with a scope other than the configured one",
			func(c jwt.MapClaims) { c["scp"] = "a3s.exchange" },
			"missing scope",
		},
		{
			"in version 1.0",
			func(c jwt.MapClaims) { c["ver"] = "1.0" },
			"unsupported token version",
		},
		{
			"with a group overage",
			func(c jwt.MapClaims) {
				delete(c, "groups")
				c["_claim_names"] = map[string]string{"groups": "src1"}
				c["_claim_sources"] = map[string]any{
					"src1": map[string]string{"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"},
				}
			},
			"group overage is not supported",
		},
		{
			"that expired",
			func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
			"token is expired",
		},
		{
			"not valid yet",
			func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
			"before the nbf",
		},
	}

	for _, tt := range tests {
		Convey("Given a token "+tt.name, t, func() {

			claims := entra.claims()
			tt.modify(claims)

			iss, err := New(context.Background(), makeTestSource(), entra.sign(t, entra.key, claims), entra.config(), nil)

			if tt.want == "" {
				So(err, ShouldBeNil)
				return
			}

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, tt.want)
			So(iss, ShouldBeNil)
		})
	}
}
