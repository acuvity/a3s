package oauthserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/token"
)

// fakeStore keeps authorize contexts and sessions in memory. It honours the
// single-use contract the Redis store guarantees with Lua: the first
// invalidation of a code wins and every later one reports it as used.
type fakeStore struct {
	contexts map[string]*AuthorizeContext
	sessions map[string]*Session
	used     map[string]bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		contexts: map[string]*AuthorizeContext{},
		sessions: map[string]*Session{},
		used:     map[string]bool{},
	}
}

func (s *fakeStore) createAuthorizeContext(authorizeContext *AuthorizeContext) error {
	copyContext := *authorizeContext
	s.contexts[authorizeContext.ID] = &copyContext
	return nil
}

func (s *fakeStore) getAuthorizeContext(id string) (*AuthorizeContext, error) {
	authorizeContext, ok := s.contexts[id]
	if !ok {
		return nil, ErrNotFound
	}

	copyContext := *authorizeContext
	return &copyContext, nil
}

func (s *fakeStore) createOAuthSession(session *Session) error {
	copySession := *session
	s.sessions[session.Code] = &copySession
	return nil
}

func (s *fakeStore) getOAuthSession(code string) (*Session, error) {
	session, ok := s.sessions[code]
	if !ok {
		return nil, ErrNotFound
	}

	copySession := *session
	return &copySession, nil
}

func (s *fakeStore) invalidateOAuthSession(code string) error {
	if _, ok := s.sessions[code]; !ok {
		return ErrNotFound
	}
	if s.used[code] {
		return ErrAuthorizationCodeUsed
	}

	s.used[code] = true
	return nil
}

// authorizeParams is a valid authorize request for the fixture client.
func (f *tokenExchangeFixture) authorizeParams(scope string) url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {f.client.ClientID},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"scope":         {scope},
	}
}

// codeFor drives an authorize request and then plays the part of the login
// ceremony, resuming the flow through the same exported calls /issue makes
// once a source has authenticated the user. It returns the authorization code.
func (f *tokenExchangeFixture) codeFor(t *testing.T, params url.Values, identity []string) string {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize Location: %v", err)
	}

	authorizeContext, oauthClient, oauthApplication, err := f.oauth.LoadAuthorizeContext(
		context.Background(),
		location.Query().Get("authorizeRequestID"),
	)
	if err != nil {
		t.Fatalf("LoadAuthorizeContext() error = %v", err)
	}

	idt := token.NewIdentityToken(f.identitySource)
	idt.Identity = identity
	idt.Subject = f.subject
	idt.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(time.Hour))

	redirectURL, err := f.oauth.CompleteAuthorize(idt, authorizeContext, oauthClient, oauthApplication)
	if err != nil {
		t.Fatalf("CompleteAuthorize() error = %v", err)
	}

	redirect, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", redirectURL, err)
	}

	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect %q carries no code", redirectURL)
	}

	return code
}

// redeemCode posts an authorization_code request for the given code.
func (f *tokenExchangeFixture) redeemCode(t *testing.T, code string) tokenEndpointResponse {
	t.Helper()

	return f.post(t, url.Values{
		"grant_type":   {oauthGrantTypeAuthorizationCode},
		"code":         {code},
		"redirect_uri": {f.client.RedirectURIs[0]},
	}, true)
}

func TestAuthorizationCodeGrantIssuesIDTokenForOpenIDScope(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	params := fixture.authorizeParams("openid profile")
	params.Set("nonce", "nonce-1")

	code := fixture.codeFor(t, params, []string{
		"sub=1234",
		"email=user@example.com",
		"name=Some One",
	})

	response := fixture.redeemCode(t, code)
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	// The access token is unchanged by this: still an a3s token addressed to
	// the application.
	accessToken, ok := response.payload["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("response missing access_token")
	}
	if _, err := token.Parse(accessToken, fixture.jwks, fixture.oauthIssuer(), fixture.app.Audience); err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}

	rawIDToken, ok := response.payload["id_token"].(string)
	if !ok || rawIDToken == "" {
		t.Fatal("response missing id_token")
	}

	claims := fixture.parseIDToken(t, rawIDToken, fixture.client.ClientID)
	assertIDTokenClaims(t, claims, map[string]any{
		"iss": fixture.oauthIssuer(),
		"aud": fixture.client.ClientID,
		// Derived when the identity was authenticated, from the claim the
		// source nominates, rather than copied from the upstream sub.
		"sub":   testSubject,
		"email": "user@example.com",
		"name":  "Some One",
		"nonce": "nonce-1",
	})
	assertIDTokenIsFlat(t, claims)

	// The ID Token addresses the client, so it is not valid for the resource
	// the access token grants access to.
	if fixture.idTokenValidFor(rawIDToken, fixture.app.Audience) {
		t.Error("ID Token must not be valid for the application audience")
	}
}

func TestAuthorizationCodeGrantOmitsIDTokenWithoutOpenIDScope(t *testing.T) {
	// Without openid the request is an authorization request rather than an
	// authentication request, so there is nothing to assert about a user.
	fixture := newTokenExchangeFixture(t)

	code := fixture.codeFor(t, fixture.authorizeParams("profile"), []string{"sub=1234"})

	response := fixture.redeemCode(t, code)
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}
	if _, ok := response.payload["access_token"]; !ok {
		t.Error("response missing access_token")
	}
	if got, ok := response.payload["id_token"]; ok {
		t.Errorf("id_token = %#v, want absent", got)
	}
}

func TestAuthorizationCodeGrantOmitsNonceWhenRequestSentNone(t *testing.T) {
	// Echoing a nonce the request never carried would fail a relying party
	// that sent none.
	fixture := newTokenExchangeFixture(t)

	code := fixture.codeFor(t, fixture.authorizeParams("openid"), []string{"sub=1234"})

	response := fixture.redeemCode(t, code)
	claims := fixture.parseIDToken(t, response.payload["id_token"].(string), fixture.client.ClientID)

	if got, ok := claims["nonce"]; ok {
		t.Errorf("nonce = %#v, want absent", got)
	}
}

func TestAuthorizeScopeAllowlistAppliesOnlyWhenTheClientListsScopes(t *testing.T) {
	for _, test := range []struct {
		name          string
		clientScopes  []string
		defaultScopes []string
		scope         string
		wantError     string
	}{
		{
			name:         "an absent list accepts any requested scope",
			clientScopes: nil,
			scope:        "openid email mcp",
		},
		{
			// An empty list means the same as an absent one: null and [] are
			// swapped by any number of round trips.
			name:         "an empty list accepts any requested scope",
			clientScopes: []string{},
			scope:        "openid email mcp",
		},
		{
			name:         "a list accepts the scopes it names",
			clientScopes: []string{"openid", "email"},
			scope:        "openid email",
		},
		{
			name:         "a list refuses a scope it omits",
			clientScopes: []string{"openid"},
			scope:        "openid email",
			wantError:    "invalid_scope",
		},
		{
			// The same rule covers the scopes the application falls back to
			// when the client requests none.
			name:          "an absent list accepts any default scope",
			clientScopes:  nil,
			defaultScopes: []string{"openid", "mcp"},
		},
		{
			name:          "a list refuses a default scope it omits",
			clientScopes:  []string{"openid"},
			defaultScopes: []string{"openid", "mcp"},
			wantError:     "invalid_scope",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTokenExchangeFixture(t)
			fixture.client.Scopes = test.clientScopes
			fixture.app.DefaultScopes = test.defaultScopes

			params := fixture.authorizeParams(test.scope)
			params.Set("state", "state-1")
			if test.scope == "" {
				params.Del("scope")
			}

			request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
			recorder := httptest.NewRecorder()
			fixture.handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
			}

			location, err := url.Parse(recorder.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}

			if test.wantError == "" {
				if got := location.Query().Get("authorizeRequestID"); got == "" {
					t.Fatalf("request was refused: %s", recorder.Header().Get("Location"))
				}
				return
			}

			// A refusal goes back to the client, carrying its state.
			if got := location.Query().Get("error"); got != test.wantError {
				t.Errorf("error = %q, want %q", got, test.wantError)
			}
			if got := location.Query().Get("state"); got != "state-1" {
				t.Errorf("state = %q, want %q", got, "state-1")
			}
		})
	}
}

func TestAuthorizationCodeGrantFailsWhenIdentityNamesNoSubject(t *testing.T) {
	// A source naming no subject leaves the identity without one, and OIDC
	// Core section 2 makes sub required in an ID Token. The request is refused
	// rather than answered with a token no relying party could accept.
	fixture := newTokenExchangeFixture(t)
	fixture.withoutSubject()

	code := fixture.codeFor(t, fixture.authorizeParams("openid"), []string{"commonname=some-cert"})

	response := fixture.redeemCode(t, code)

	if response.status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
	}
	if response.payload["error"] != "invalid_request" {
		t.Errorf("error = %v, want %q", response.payload["error"], "invalid_request")
	}
	if _, ok := response.payload["id_token"]; ok {
		t.Error("a refused request must not carry an id_token")
	}
}
