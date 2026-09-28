package oauthserver

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
)

// refreshTokenFor runs a full authorization-code grant for the given scope and
// returns the refresh token it issued.
func (f *tokenExchangeFixture) refreshTokenFor(t *testing.T, scope string) string {
	t.Helper()

	params := f.authorizeParams(scope)
	params.Set("nonce", "nonce-1")

	response := f.redeemCode(t, f.codeFor(t, params, []string{"sub=1234", "email=user@example.com"}))
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	refreshToken, ok := response.payload["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatal("response missing refresh_token")
	}

	return refreshToken
}

// refresh posts a refresh_token request, narrowing the grant to scope when it
// is not empty.
func (f *tokenExchangeFixture) refresh(t *testing.T, refreshToken string, scope string) tokenEndpointResponse {
	t.Helper()

	form := url.Values{
		"grant_type":    {oauthGrantTypeRefreshToken},
		"refresh_token": {refreshToken},
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	return f.post(t, form, true)
}

// assertOAuthError fails unless the token endpoint refused the request with
// the given RFC 6749 section 5.2 error, which it answers with a 400.
func assertOAuthError(t *testing.T, response tokenEndpointResponse, wantError string) {
	t.Helper()

	if response.status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
	}
	if response.payload["error"] != wantError {
		t.Fatalf("error = %v, want %q", response.payload["error"], wantError)
	}
}

func TestAuthorizationCodeGrantIssuesRefreshToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	refreshToken := fixture.refreshTokenFor(t, "openid profile")

	idt, err := token.Parse(refreshToken, fixture.jwks, fixture.oauthIssuer(), fixture.oauthIssuer())
	if err != nil {
		t.Fatalf("refresh token does not verify: %v", err)
	}
	if !idt.Refresh {
		t.Error("refresh token is not flagged as a refresh token")
	}
	if idt.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", idt.Scope, "openid profile")
	}
	if idt.OAuthClient.ClientID != fixture.client.ClientID {
		t.Errorf("client = %q, want %q", idt.OAuthClient.ClientID, fixture.client.ClientID)
	}

	// Without an application setting, the server default applies, and it is
	// not capped by the authentication the code froze.
	if got := time.Until(idt.ExpiresAt.Time); got < testRefreshValidity-time.Minute || got > testRefreshValidity {
		t.Errorf("refresh token lifetime = %s, want %s", got, testRefreshValidity)
	}

	// A refresh token must never be usable as an access token.
	if _, err := token.Parse(refreshToken, fixture.jwks, fixture.oauthIssuer(), fixture.app.Audience); err == nil {
		t.Error("refresh token must not be valid for the application audience")
	}
}

func TestAuthorizationCodeGrantUsesApplicationRefreshTokenValidity(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	fixture.app.RefreshTokenValidity = "2h"

	idt, err := token.Parse(fixture.refreshTokenFor(t, "profile"), fixture.jwks, fixture.oauthIssuer(), fixture.oauthIssuer())
	if err != nil {
		t.Fatalf("refresh token does not verify: %v", err)
	}

	if got := time.Until(idt.ExpiresAt.Time); got < 2*time.Hour-time.Minute || got > 2*time.Hour {
		t.Errorf("refresh token lifetime = %s, want %s", got, 2*time.Hour)
	}
}

func TestRefreshTokenGrantMintsAccessAndIDTokens(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "openid profile")

	response := fixture.refresh(t, refreshToken, "")
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	if response.payload["token_type"] != tokenTypeBearer {
		t.Errorf("token_type = %v, want %q", response.payload["token_type"], tokenTypeBearer)
	}
	// Refresh tokens are not rotated.
	if _, ok := response.payload["refresh_token"]; ok {
		t.Error("response must not carry a new refresh_token")
	}
	if response.payload["scope"] != "openid profile" {
		t.Errorf("scope = %v, want %q", response.payload["scope"], "openid profile")
	}

	accessToken, _ := response.payload["access_token"].(string)
	idt, err := token.Parse(accessToken, fixture.jwks, fixture.oauthIssuer(), fixture.app.Audience)
	if err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}
	if idt.Refresh || idt.Scope != "" {
		t.Errorf("access token carries refresh state: refresh=%t scope=%q", idt.Refresh, idt.Scope)
	}
	if idt.Subject != testSubject {
		t.Errorf("sub = %q, want %q", idt.Subject, testSubject)
	}
	if got := time.Until(idt.ExpiresAt.Time); got > 5*time.Minute {
		t.Errorf("access token lifetime = %s, want at most %s", got, 5*time.Minute)
	}

	// Signing again must not double the claims signing derives.
	count := 0
	for _, claim := range idt.Identity {
		if claim == "@source:type=oidc" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("@source:type appears %d times, want 1: %v", count, idt.Identity)
	}

	rawIDToken, _ := response.payload["id_token"].(string)
	if rawIDToken == "" {
		t.Fatal("response missing id_token")
	}
	claims := fixture.parseIDToken(t, rawIDToken, fixture.client.ClientID)
	assertIDTokenClaims(t, claims, map[string]any{
		"iss":   fixture.oauthIssuer(),
		"aud":   fixture.client.ClientID,
		"sub":   testSubject,
		"email": "user@example.com",
	})
	// OIDC Core section 12.2: a refreshed ID Token carries no nonce.
	if _, ok := claims["nonce"]; ok {
		t.Error("refreshed id token must not carry a nonce")
	}
}

func TestRefreshTokenGrantCanBeRepeated(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	for i := range 2 {
		if response := fixture.refresh(t, refreshToken, ""); response.status != http.StatusOK {
			t.Fatalf("refresh %d: status = %d (%s), want %d", i, response.status, response.body, http.StatusOK)
		}
	}
}

func TestRefreshTokenGrantNarrowsScope(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "openid profile")

	response := fixture.refresh(t, refreshToken, "profile")
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	// Without openid the refresh is no longer an authentication request.
	if _, ok := response.payload["id_token"]; ok {
		t.Error("response must not carry an id_token once openid is dropped")
	}
	// The scope granted is the one requested, so it need not be restated.
	if _, ok := response.payload["scope"]; ok {
		t.Errorf("scope = %v, want none", response.payload["scope"])
	}
}

func TestRefreshTokenGrantRejectsWiderScope(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	assertOAuthError(t, fixture.refresh(t, refreshToken, "openid profile"), "invalid_scope")
}

func TestRefreshTokenGrantRejectsDisabledApplication(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	fixture.manipulator.app = withDisabled(fixture.app, true)

	assertOAuthError(t, fixture.refresh(t, refreshToken, ""), "invalid_grant")
}

func TestRefreshTokenGrantRejectsOtherClient(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	other := *fixture.client
	other.ClientID = "client-2"
	fixture.manipulator.client = &other
	fixture.client = &other

	assertOAuthError(t, fixture.refresh(t, refreshToken, ""), "invalid_grant")
}

func TestRefreshTokenGrantRequiresClient(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	response := fixture.exchangeAnonymously(t, url.Values{
		"grant_type":    {oauthGrantTypeRefreshToken},
		"refresh_token": {refreshToken},
	})

	assertOAuthError(t, response, "invalid_client")
}

func TestRefreshTokenGrantRejectsUnacceptableTokens(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	issuer := fixture.oauthIssuer()

	tests := map[string]string{
		"missing": "",
		"garbage": "not-a-token",
		// An access token of this issuer, addressed to the application.
		"access token": fixture.mintSubjectToken(t, issuer, fixture.app.Audience, nil),
		// A token addressed to the issuer, but not flagged as refresh.
		"not flagged refresh": fixture.mintSubjectToken(t, issuer, issuer, nil),
		"expired": fixture.mintSubjectToken(t, issuer, issuer, func(idt *token.IdentityToken) {
			idt.Refresh = true
			idt.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
		}),
		"native a3s refresh token": fixture.mintSubjectToken(t, fixture.a3sIssuer, testA3SAudience, func(idt *token.IdentityToken) {
			idt.Refresh = true
		}),
	}

	for name, refreshToken := range tests {
		t.Run(name, func(t *testing.T) {
			want := "invalid_grant"
			if refreshToken == "" {
				want = "invalid_request"
			}
			assertOAuthError(t, fixture.refresh(t, refreshToken, ""), want)
		})
	}
}

func TestRefreshTokenGrantChecksRevocation(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	unverified, err := token.ParseUnverified(refreshToken)
	if err != nil {
		t.Fatalf("ParseUnverified() error = %v", err)
	}

	var gotNamespace, gotTokenID string
	var gotClaims []string
	var gotIAT time.Time
	fixture.revocations.revoked = func(namespace string, tokenID string, claims []string, iat time.Time) (bool, error) {
		gotNamespace, gotTokenID, gotClaims, gotIAT = namespace, tokenID, claims, iat
		return true, nil
	}

	assertOAuthError(t, fixture.refresh(t, refreshToken, ""), "invalid_grant")

	// The check is asked about the refresh token itself, with the full
	// identity so subject revocations can match derived claims too.
	if gotNamespace != "/" {
		t.Errorf("namespace = %q, want %q", gotNamespace, "/")
	}
	if gotTokenID != unverified.ID {
		t.Errorf("token ID = %q, want %q", gotTokenID, unverified.ID)
	}
	if !gotIAT.Equal(unverified.IssuedAt.Time) {
		t.Errorf("iat = %s, want %s", gotIAT, unverified.IssuedAt.Time)
	}
	found := false
	for _, claim := range gotClaims {
		if claim == "@oauthclient:clientid="+fixture.client.ClientID {
			found = true
		}
	}
	if !found {
		t.Errorf("claims %v do not carry the derived oauth client claim", gotClaims)
	}
}

func TestRefreshTokenGrantFailsWhenRevocationCheckFails(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	fixture.revocations.revoked = func(string, string, []string, time.Time) (bool, error) {
		return false, errors.New("database unavailable")
	}

	// An unanswered revocation check must never let the grant through.
	response := fixture.refresh(t, refreshToken, "")
	if response.status == http.StatusOK {
		t.Fatalf("status = %d, want a failure", response.status)
	}
}

// A refresh token must not be accepted wherever an access token is.
func TestRefreshTokenIsRefusedAsAccessToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "openid profile")

	if _, err := fixture.oauth.userinfo("/", refreshToken); err == nil {
		t.Error("userinfo accepted a refresh token")
	}

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {refreshToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"partner"},
	})
	assertOAuthError(t, response, "invalid_request")
}

func TestRefreshTokenValidityFallsBackToServerDefault(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	for _, validity := range []string{"", "frog", "0s", "-1h"} {
		app := &api.OAuthApplication{RefreshTokenValidity: validity}
		if got := fixture.oauth.refreshTokenValidity(app); got != testRefreshValidity {
			t.Errorf("refreshTokenValidity(%q) = %s, want %s", validity, got, testRefreshValidity)
		}
	}
}

func TestAuthorizationCodeGrantSkipsExpiredRefreshToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	fixture.app.RefreshTokenValidity = "1ns"

	params := fixture.authorizeParams("profile")
	response := fixture.redeemCode(t, fixture.codeFor(t, params, []string{"sub=1234"}))
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	// The refresh token ran out between authorize and redemption, so the
	// grant still answers with an access token, but with no refresh token.
	if _, ok := response.payload["access_token"]; !ok {
		t.Error("response missing access_token")
	}
	if _, ok := response.payload["refresh_token"]; ok {
		t.Error("response must not carry an already expired refresh_token")
	}
}

func TestRefreshTokenGrantRejectsReassignedClient(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	// The same client now serves another application.
	other := *fixture.app
	other.ID = "oauthapp-2"
	other.Audience = "api://other"
	fixture.manipulator.app = &other
	client := *fixture.client
	client.OauthApplicationID = other.ID
	fixture.manipulator.client = &client

	assertOAuthError(t, fixture.refresh(t, refreshToken, ""), "invalid_grant")
}

func TestRefreshTokenGrantRechecksClientScopes(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "openid profile")

	client := *fixture.client
	client.Scopes = []string{"profile"}
	fixture.manipulator.client = &client

	assertOAuthError(t, fixture.refresh(t, refreshToken, ""), "invalid_scope")

	// The client can still narrow its grant to what remains allowed.
	if response := fixture.refresh(t, refreshToken, "profile"); response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}
}

func TestRefreshTokenGrantRechecksAllowedSources(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	refreshToken := fixture.refreshTokenFor(t, "profile")

	fixture.manipulator.oidc = &api.OIDCSource{
		Name:      testIdentitySource.Name,
		Namespace: testIdentitySource.Namespace,
	}

	allowed := *fixture.app
	allowed.AllowedSources = []string{`name == "corp"`}
	fixture.manipulator.app = &allowed
	if response := fixture.refresh(t, refreshToken, ""); response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	denied := *fixture.app
	denied.AllowedSources = []string{`name == "other"`}
	fixture.manipulator.app = &denied
	assertOAuthError(t, fixture.refresh(t, refreshToken, ""), "invalid_grant")

	// A source that was deleted since cannot be matched at all.
	fixture.manipulator.oidc = nil
	fixture.manipulator.app = &allowed
	assertOAuthError(t, fixture.refresh(t, refreshToken, ""), "invalid_grant")
}
