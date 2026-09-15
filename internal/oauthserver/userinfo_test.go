package oauthserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/token"
)

// getUserinfo calls the userinfo endpoint with the given bearer credential,
// sent verbatim so a test controls the exact Authorization header.
func getUserinfo(t *testing.T, handler *HTTPHandler, authorization string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder
}

// mintUserinfoToken signs an access token the way the authorization-code grant
// does, carrying the given identity claims.
func (f *tokenExchangeFixture) mintUserinfoToken(t *testing.T, identity []string) string {
	t.Helper()

	idt := token.NewIdentityToken(f.identitySource)
	idt.Identity = identity
	idt.Subject = f.subject
	idt.OAuthApplication = token.OAuthApplication{
		ID:        f.app.ID,
		Namespace: f.app.Namespace,
		Name:      f.app.Name,
	}

	signed, _, err := f.oauth.signToken(
		"/",
		idt,
		jwt.ClaimStrings{f.app.Audience},
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("signToken() error = %v", err)
	}

	return signed
}

func TestUserinfoReturnsIdentityClaims(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	accessToken := fixture.mintUserinfoToken(t, []string{
		"sub=1234",
		"email=user@example.com",
		"name=Some One",
		"groups=admins",
		"groups=devs",
		"@source:type=oidc",
		"@issuer=https://issuer.example/oauth",
	})

	recorder := getUserinfo(t, fixture.handler, "Bearer "+accessToken)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	claims := map[string]any{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}

	for field, want := range map[string]any{
		"sub":   testSubject,
		"email": "user@example.com",
		"name":  "Some One",
	} {
		if got := claims[field]; got != want {
			t.Errorf("%s = %#v, want %#v", field, got, want)
		}
	}

	// A claim the source repeats becomes an array.
	groups, ok := claims["groups"].([]any)
	if !ok || len(groups) != 2 || groups[0] != "admins" || groups[1] != "devs" {
		t.Errorf("groups = %#v, want [admins devs]", claims["groups"])
	}

	// Derived claims describe how a3s reached the identity, not the
	// identity, and must not leak into the response.
	for _, field := range []string{"@source:type", "source:type", "@issuer", "issuer"} {
		if _, ok := claims[field]; ok {
			t.Errorf("response leaks derived claim %q: %#v", field, claims)
		}
	}

	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestUserinfoDropsUpstreamProtocolClaims(t *testing.T) {
	// computeOIDClaims copies the upstream ID token whole, so the source's
	// own iss, aud and exp arrive in the identity, as do the claims binding
	// that token to its own client, access token and session. They describe
	// the upstream token, not this one, and must not be reported as claims
	// about the user.
	fixture := newTokenExchangeFixture(t)
	accessToken := fixture.mintUserinfoToken(t, []string{
		"iss=https://okta.example",
		"aud=okta-client-id",
		"exp=1700000000",
		"iat=1700000000",
		"nbf=1700000000",
		"jti=upstream-jti",
		"nonce=upstream-nonce",
		"azp=okta-client-id",
		"at_hash=upstream-at-hash",
		"c_hash=upstream-c-hash",
		"sid=upstream-session",
		"auth_time=1700000000",
		"sub=1234",
		"email=user@example.com",
	})

	recorder := getUserinfo(t, fixture.handler, "Bearer "+accessToken)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	claims := map[string]any{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}

	for _, field := range []string{
		"iss", "aud", "exp", "iat", "nbf", "jti", "nonce",
		"azp", "at_hash", "c_hash", "sid", "auth_time",
	} {
		if got, ok := claims[field]; ok {
			t.Errorf("response leaks upstream claim %q = %#v", field, got)
		}
	}

	// auth_time is dropped with them. A source stringifies every claim it
	// copies, and OIDC Core section 2 types auth_time as a number, so a
	// relying party rejects the token rather than the claim.

	// The ordinary claims still come through, and the subject is derived from
	// the upstream sub that was dropped with the rest of them.
	for field, want := range map[string]any{
		"sub":   testSubject,
		"email": "user@example.com",
	} {
		if got := claims[field]; got != want {
			t.Errorf("%s = %#v, want %#v", field, got, want)
		}
	}
}

func TestUserinfoFailsWhenSourceNamesNoSubClaim(t *testing.T) {
	// OIDC Core section 5.3.2 makes sub the one claim a userinfo response must
	// always carry, so a source that names no subject fails the request rather
	// than answering with a body no relying party could accept.
	fixture := newTokenExchangeFixture(t)
	fixture.withoutSubject()

	accessToken := fixture.mintUserinfoToken(t, []string{"commonname=some-cert"})

	recorder := getUserinfo(t, fixture.handler, "Bearer "+accessToken)

	if recorder.Code == http.StatusOK {
		t.Fatalf("status = %d, want a failure: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(got, "invalid_request") {
		t.Errorf("WWW-Authenticate = %q, want it to name invalid_request", got)
	}
	if strings.Contains(recorder.Body.String(), "some-cert") {
		t.Errorf("a refused request must not leak identity claims: %s", recorder.Body.String())
	}
}

func TestUserinfoRejectsMissingBearerToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	for _, test := range []struct {
		name          string
		authorization string
	}{
		{"no header", ""},
		{"wrong scheme", "Basic Y2xpZW50LTE6c2VjcmV0LTE="},
		{"empty credential", "Bearer "},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := getUserinfo(t, fixture.handler, test.authorization)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
			}
			// RFC 6750 section 3.1: a request carrying no credential is
			// challenged without an error code.
			if got := recorder.Header().Get("WWW-Authenticate"); got != `Bearer realm="oauth"` {
				t.Errorf("WWW-Authenticate = %q, want %q", got, `Bearer realm="oauth"`)
			}
		})
	}
}

func TestUserinfoRejectsForeignIssuer(t *testing.T) {
	// A token minted for another namespace's OAuth surface, or by something
	// else entirely, must not resolve here.
	fixture := newTokenExchangeFixture(t)
	accessToken := fixture.mintSubjectToken(t, "https://elsewhere.example/oauth", "api://portal", nil)

	recorder := getUserinfo(t, fixture.handler, "Bearer "+accessToken)

	assertOAuthJSONField(t, recorder, http.StatusUnauthorized, "error", "invalid_token")
	if got, want := recorder.Header().Get("WWW-Authenticate"), `Bearer realm="oauth", error="invalid_token"`; got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestUserinfoRejectsNativeA3SToken(t *testing.T) {
	// The token exchange accepts native a3s tokens, the OIDC surface does
	// not: it describes the OAuth surface, so it serves only tokens obtained
	// through an oauth application.
	fixture := newTokenExchangeFixture(t)
	accessToken := fixture.mintSubjectToken(t, fixture.a3sIssuer, testA3SAudience, nil)

	recorder := getUserinfo(t, fixture.handler, "Bearer "+accessToken)

	assertOAuthJSONField(t, recorder, http.StatusUnauthorized, "error", "invalid_token")
}

func TestUserinfoRejectsTokenNamingNoOAuthApplication(t *testing.T) {
	// Signed by this issuer, but naming no application, so it did not come
	// from an oauth application's flow.
	fixture := newTokenExchangeFixture(t)
	accessToken := fixture.mintSubjectToken(
		t,
		fixture.oauthIssuer(),
		fixture.app.Audience,
		func(idt *token.IdentityToken) { idt.OAuthApplication = token.OAuthApplication{} },
	)

	recorder := getUserinfo(t, fixture.handler, "Bearer "+accessToken)

	assertOAuthJSONField(t, recorder, http.StatusUnauthorized, "error_description", "access token names no oauth application")
}

func TestUserinfoRejectsGarbageToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	recorder := getUserinfo(t, fixture.handler, "Bearer not-a-jwt")

	assertOAuthJSONField(t, recorder, http.StatusUnauthorized, "error", "invalid_token")
}

func TestUserinfoRejectsNonGETOrPOST(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	request := httptest.NewRequest(http.MethodDelete, "/oauth/userinfo", nil)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)

	assertOAuthJSONField(t, recorder, http.StatusMethodNotAllowed, "error", "invalid_request")
	if got := recorder.Header().Get("Allow"); got != "GET, POST" {
		t.Errorf("Allow = %q, want %q", got, "GET, POST")
	}
}
