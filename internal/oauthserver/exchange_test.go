package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
)

const testA3SAudience = "a3s"

func TestOAuthTokenExchangeMintsIDTokenFromOAuthAccessToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", func(idt *token.IdentityToken) {
		idt.Identity = []string{"email=user@example.com", "org=acme"}
		idt.Opaque = map[string]string{"tenant": "acme"}
	})

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"https://partner.example"},
	})

	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}
	if response.payload["issued_token_type"] != oauthTokenTypeIDToken {
		t.Fatalf("issued_token_type = %v, want %q", response.payload["issued_token_type"], oauthTokenTypeIDToken)
	}
	if response.payload["token_type"] != tokenTypeNotApplicable {
		t.Fatalf("token_type = %v, want %q", response.payload["token_type"], tokenTypeNotApplicable)
	}
	if _, ok := response.payload["scope"]; ok {
		t.Fatalf("response must not carry a scope, got %v", response.payload["scope"])
	}

	idToken, ok := response.payload["access_token"].(string)
	if !ok || idToken == "" {
		t.Fatal("response missing access_token")
	}

	// The ID token must verify against the issuer of the OAuth surface it was
	// requested from, and only for the requested audience.
	issued, err := token.Parse(idToken, fixture.jwks, fixture.oauthIssuer(), "https://partner.example")
	if err != nil {
		t.Fatalf("token.Parse() error = %v", err)
	}

	if got := issued.Audience; len(got) != 1 || got[0] != "https://partner.example" {
		t.Fatalf("aud = %v, want [https://partner.example]", got)
	}
	if _, err := token.Parse(idToken, fixture.jwks, fixture.oauthIssuer(), "api://portal"); err == nil {
		t.Fatal("ID token must not be valid for the original access token audience")
	}
	if _, err := token.Parse(idToken, fixture.jwks, fixture.oauthIssuer(), testA3SAudience); err == nil {
		t.Fatal("ID token must not be valid for the a3s audience")
	}

	assertClaim(t, issued.Identity, "email=user@example.com")
	assertClaim(t, issued.Identity, "org=acme")
	assertClaim(t, issued.Identity, "@source:type=OIDC")
	assertClaim(t, issued.Identity, "@source:name=corp")
	assertClaim(t, issued.Identity, "@issuer="+fixture.oauthIssuer())

	if len(issued.Opaque) != 0 {
		t.Fatalf("opaque = %v, want empty", issued.Opaque)
	}

	// A subject token minted with the same @issuer claim must not leave a
	// stale duplicate behind after re-issuance.
	if got := countClaimsWithPrefix(issued.Identity, "@issuer="); got != 1 {
		t.Fatalf("@issuer claim count = %d, want 1", got)
	}
}

func TestOAuthTokenExchangeAcceptsNativeA3SToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	subjectToken := fixture.mintSubjectToken(t, fixture.a3sIssuer, testA3SAudience, nil)

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeJWT},
		"audience":           {"partner"},
	})

	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	// A native a3s token names no oauth application, so it is checked against
	// the a3s audience instead.
	issued, err := token.Parse(response.payload["access_token"].(string), fixture.jwks, fixture.oauthIssuer(), "partner")
	if err != nil {
		t.Fatalf("token.Parse() error = %v", err)
	}
	if got := issued.Audience; len(got) != 1 || got[0] != "partner" {
		t.Fatalf("aud = %v, want [partner]", got)
	}
}

func TestOAuthTokenExchangePreservesRestrictionsAndCapsExpiration(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	subjectExpiration := time.Now().UTC().Add(3 * time.Minute).Truncate(time.Second)
	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", func(idt *token.IdentityToken) {
		idt.ExpiresAt = jwt.NewNumericDate(subjectExpiration)
		idt.Restrictions = &permissions.Restrictions{
			Namespace: "/acme/dev",
			Networks:  []string{"10.0.0.0/8"},
		}
	})

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"client-1"},
	})

	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	// The engine default validity is 5 minutes, so an uncapped implementation
	// would outlive the subject token here.
	expiresIn, ok := response.payload["expires_in"].(float64)
	if !ok {
		t.Fatalf("expires_in = %v, want a number", response.payload["expires_in"])
	}
	if expiresIn <= 0 || expiresIn > 180 {
		t.Fatalf("expires_in = %v, want 0 < expires_in <= 180", expiresIn)
	}

	issued, err := token.Parse(response.payload["access_token"].(string), fixture.jwks, fixture.oauthIssuer(), "client-1")
	if err != nil {
		t.Fatalf("token.Parse() error = %v", err)
	}
	if !issued.ExpiresAt.Time.Equal(subjectExpiration) {
		t.Fatalf("exp = %s, want %s", issued.ExpiresAt.Time, subjectExpiration)
	}
	if issued.Restrictions == nil || issued.Restrictions.Namespace != "/acme/dev" {
		t.Fatalf("restrictions = %#v, want namespace /acme/dev", issued.Restrictions)
	}
	if issued.Restrictions == nil || len(issued.Restrictions.Networks) != 1 || issued.Restrictions.Networks[0] != "10.0.0.0/8" {
		t.Fatalf("restricted networks = %#v, want [10.0.0.0/8]", issued.Restrictions)
	}
}

// A3S targets the issued evidence through audience alone. A resource
// indicator is refused rather than dropped, so a caller that names a target
// a3s will not honor learns about it.
func TestOAuthTokenExchangeRejectsResourceIndicator(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", nil)

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"resource":           {"https://mcp.example/api"},
		"audience":           {"partner"},
	})

	if response.status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
	}
	if response.payload["error"] != "invalid_target" {
		t.Fatalf("error = %v, want %q", response.payload["error"], "invalid_target")
	}
}

func TestOAuthTokenExchangeRejectsInvalidRequests(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	validSubject := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", nil)

	testCases := []struct {
		name            string
		form            url.Values
		wantError       string
		wantDescription string
	}{
		{
			name: "missing subject token",
			form: url.Values{
				"subject_token_type": {oauthTokenTypeAccessToken},
			},
			wantError:       "invalid_request",
			wantDescription: "missing subject_token",
		},
		{
			name: "missing subject token type",
			form: url.Values{
				"subject_token": {validSubject},
			},
			wantError:       "invalid_request",
			wantDescription: "missing subject_token_type",
		},
		{
			name: "unsupported subject token type",
			form: url.Values{
				"subject_token":      {validSubject},
				"subject_token_type": {"urn:ietf:params:oauth:token-type:saml2"},
			},
			wantError:       "invalid_request",
			wantDescription: `unsupported subject_token_type "urn:ietf:params:oauth:token-type:saml2"`,
		},
		{
			name: "requesting an access token is refused",
			form: url.Values{
				"subject_token":        {validSubject},
				"subject_token_type":   {oauthTokenTypeAccessToken},
				"requested_token_type": {oauthTokenTypeAccessToken},
			},
			wantError:       "invalid_request",
			wantDescription: `unsupported requested_token_type "urn:ietf:params:oauth:token-type:access_token", this endpoint only issues urn:ietf:params:oauth:token-type:id_token`,
		},
		{
			name: "delegation is refused",
			form: url.Values{
				"subject_token":      {validSubject},
				"subject_token_type": {oauthTokenTypeAccessToken},
				"actor_token":        {validSubject},
				"actor_token_type":   {oauthTokenTypeAccessToken},
			},
			wantError:       "invalid_request",
			wantDescription: "delegation through actor_token is not supported",
		},
		{
			name: "unparseable subject token",
			form: url.Values{
				"subject_token":      {"not-a-jwt"},
				"subject_token_type": {oauthTokenTypeAccessToken},
				"audience":           {"partner"},
			},
			wantError: "invalid_request",
		},
		{
			name: "missing audience",
			form: url.Values{
				"subject_token":      {validSubject},
				"subject_token_type": {oauthTokenTypeAccessToken},
			},
			wantError:       "invalid_request",
			wantDescription: "token exchange requires audience",
		},
		{
			name: "resource indicator",
			form: url.Values{
				"subject_token":      {validSubject},
				"subject_token_type": {oauthTokenTypeAccessToken},
				"resource":           {"https://mcp.example/api"},
			},
			wantError:       "invalid_target",
			wantDescription: "targeting through resource is not supported, use audience",
		},
		{
			name: "a3s audience as target",
			form: url.Values{
				"subject_token":      {validSubject},
				"subject_token_type": {oauthTokenTypeAccessToken},
				"audience":           {testA3SAudience},
			},
			wantError:       "invalid_target",
			wantDescription: "the a3s audience cannot be requested",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			form := url.Values{"grant_type": {oauthGrantTypeTokenExchange}}
			for key, values := range testCase.form {
				form[key] = values
			}

			response := fixture.exchange(t, form)

			if response.status != http.StatusBadRequest {
				t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
			}
			if response.payload["error"] != testCase.wantError {
				t.Fatalf("error = %v, want %q", response.payload["error"], testCase.wantError)
			}
			if testCase.wantDescription != "" && response.payload["error_description"] != testCase.wantDescription {
				t.Fatalf("error_description = %v, want %q", response.payload["error_description"], testCase.wantDescription)
			}
		})
	}
}

func TestOAuthTokenExchangeRejectsUnacceptableSubjectTokens(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	foreignJWKS := token.NewJWKS()
	foreignCert, foreignKey := makeTestECCert(t)
	if err := foreignJWKS.AppendWithPrivate(foreignCert, foreignKey); err != nil {
		t.Fatalf("AppendWithPrivate() error = %v", err)
	}

	forgedIdentity := token.NewIdentityToken(token.Source{Type: "OIDC", Namespace: "/", Name: "corp"})
	forgedIdentity.Identity = []string{"email=attacker@example.com"}
	forgedKey := foreignJWKS.GetLastWithPrivate()
	forged, err := forgedIdentity.JWT(
		forgedKey.PrivateKey(),
		forgedKey.KID,
		fixture.oauthIssuer(),
		jwt.ClaimStrings{"api://portal"},
		time.Now().UTC().Add(time.Hour),
		nil,
	)
	if err != nil {
		t.Fatalf("JWT() error = %v", err)
	}

	testCases := []struct {
		name         string
		subjectToken string
	}{
		{
			name:         "unknown issuer",
			subjectToken: fixture.mintSubjectToken(t, "https://elsewhere.example", "api://portal", nil),
		},
		{
			name:         "wrong audience for the oauth application",
			subjectToken: fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://other", nil),
		},
		{
			name:         "a3s issuer with a non a3s audience",
			subjectToken: fixture.mintSubjectToken(t, fixture.a3sIssuer, "api://portal", nil),
		},
		{
			name: "expired",
			subjectToken: fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", func(idt *token.IdentityToken) {
				idt.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute))
			}),
		},
		{
			name: "refresh token",
			subjectToken: fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", func(idt *token.IdentityToken) {
				idt.Refresh = true
			}),
		},
		{
			name:         "signed by an unknown key",
			subjectToken: forged,
		},
		{
			name: "issued for another namespace oauth surface",
			subjectToken: fixture.mintSubjectToken(
				t,
				fixture.oauth.issuerForNamespace("/team-a"),
				"api://portal",
				nil,
			),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// The audience is always named, so each case is rejected for its
			// subject token rather than for a missing target.
			response := fixture.exchange(t, url.Values{
				"grant_type":         {oauthGrantTypeTokenExchange},
				"subject_token":      {testCase.subjectToken},
				"subject_token_type": {oauthTokenTypeAccessToken},
				"audience":           {"partner"},
			})

			if response.status != http.StatusBadRequest {
				t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
			}
			if response.payload["error"] != "invalid_request" {
				t.Fatalf("error = %v, want %q", response.payload["error"], "invalid_request")
			}
		})
	}
}

func TestOAuthTokenExchangeRejectsDisabledApplication(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", nil)

	fixture.manipulator.app = withDisabled(fixture.app, true)

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"partner"},
	})

	if response.status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
	}
	// The application is named by the subject token, not by a client, so a
	// disabled one makes the token unusable rather than the caller unknown.
	if response.payload["error"] != "invalid_request" {
		t.Fatalf("error = %v, want %q", response.payload["error"], "invalid_request")
	}
}

// RFC 8693 section 2.1 leaves client authentication to the authorization
// server, and this one takes the subject token as the authority.
func TestOAuthTokenExchangeAcceptsRequestWithoutClient(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", nil)

	response := fixture.exchangeAnonymously(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"partner"},
	})

	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	issued, err := token.Parse(response.payload["access_token"].(string), fixture.jwks, fixture.oauthIssuer(), "partner")
	if err != nil {
		t.Fatalf("token.Parse() error = %v", err)
	}
	// The application still comes from the subject token, so its claims
	// survive an exchange no client took part in.
	assertClaim(t, issued.Identity, "@oauthapp:id="+fixture.app.ID)
}

// The authorization-code grant still needs a client: its code is bound to one.
func TestOAuthAuthorizationCodeRejectsRequestWithoutClient(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	response := fixture.exchangeAnonymously(t, url.Values{
		"grant_type": {oauthGrantTypeAuthorizationCode},
		"code":       {"code-1"},
	})

	if response.status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
	}
	if response.payload["error"] != "invalid_client" {
		t.Fatalf("error = %v, want %q", response.payload["error"], "invalid_client")
	}
}

// Without a requesting client there is no party to address the evidence to by
// default, so the request must name its target.
func TestOAuthTokenExchangeRequiresTarget(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", nil)

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
	})

	if response.status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusBadRequest)
	}
	if response.payload["error"] != "invalid_request" {
		t.Fatalf("error = %v, want %q", response.payload["error"], "invalid_request")
	}
	if got := response.payload["error_description"]; got != "token exchange requires audience" {
		t.Fatalf("error_description = %v", got)
	}
}

// Opaque data belongs to the bearer of the original token and must not travel
// to the third party the evidence is addressed to.
func TestOAuthTokenExchangeDropsOpaqueData(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", func(idt *token.IdentityToken) {
		idt.Opaque = map[string]string{"internal": "secret"}
	})

	response := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"partner"},
	})

	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	issued, err := token.Parse(response.payload["access_token"].(string), fixture.jwks, fixture.oauthIssuer(), "partner")
	if err != nil {
		t.Fatalf("token.Parse() error = %v", err)
	}
	if len(issued.Opaque) != 0 {
		t.Fatalf("opaque = %v, want empty", issued.Opaque)
	}
}

// An exchanged token is evidence held by a third party. Exchanging it again
// would widen its audience one hop at a time, so its retargeted audience no
// longer matches the application it still names.
func TestOAuthTokenExchangeRejectsAlreadyExchangedToken(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", nil)

	first := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"partner"},
	})
	if first.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", first.status, first.body, http.StatusOK)
	}

	second := fixture.exchange(t, url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {first.payload["access_token"].(string)},
		"subject_token_type": {oauthTokenTypeAccessToken},
		"audience":           {"someone-else"},
	})

	if second.status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want %d", second.status, second.body, http.StatusBadRequest)
	}
	if second.payload["error"] != "invalid_request" {
		t.Fatalf("error = %v, want %q", second.payload["error"], "invalid_request")
	}
}

func TestOAuthTokenExchangeRejectsInvalidClientCredentials(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	subjectToken := fixture.mintSubjectToken(t, fixture.oauthIssuer(), "api://portal", nil)

	form := url.Values{
		"grant_type":         {oauthGrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {oauthTokenTypeAccessToken},
	}

	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("client-1", "wrong-secret")

	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)

	assertOAuthJSONField(t, recorder, http.StatusUnauthorized, "error", "invalid_client")
	if got := recorder.Header().Get("WWW-Authenticate"); got != `Basic realm="oauth"` {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, `Basic realm="oauth"`)
	}
}

func TestOAuthMetadataAdvertisesTokenExchange(t *testing.T) {
	handler := newOAuthHTTPHandlerForTest(t)

	request := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server/oauth", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assertOAuthJSONField(t, recorder, http.StatusOK, "grant_types_supported", []any{
		"authorization_code",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	})
}

// tokenExchangeFixture wires a token endpoint able to sign and verify tokens.
type tokenExchangeFixture struct {
	oauth       *OAuth
	handler     *HTTPHandler
	jwks        *token.JWKS
	manipulator *fakeManipulator
	client      *api.OAuthClient
	app         *api.OAuthApplication
	a3sIssuer   string
}

func newTokenExchangeFixture(t *testing.T) *tokenExchangeFixture {
	t.Helper()

	jwks := token.NewJWKS()
	cert, key := makeTestECCert(t)
	if err := jwks.AppendWithPrivate(cert, key); err != nil {
		t.Fatalf("AppendWithPrivate() error = %v", err)
	}

	client := &api.OAuthClient{
		ClientID:                "client-1",
		ClientSecret:            "secret-1",
		Namespace:               "/",
		OauthApplicationID:      "oauthapp-1",
		RedirectURIs:            []string{"https://client.example/callback"},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: api.OAuthClientTokenEndpointAuthMethodClientSecretBasic,
	}

	app := &api.OAuthApplication{
		ID:        "oauthapp-1",
		Namespace: "/",
		Name:      "portal",
		Audience:  "api://portal",
	}

	a3sIssuer := "https://issuer.example"
	manipulator := &fakeManipulator{client: client, app: app}
	oauth, err := NewOAuth(nil, manipulator, jwks, a3sIssuer, testA3SAudience, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewOAuth() error = %v", err)
	}

	return &tokenExchangeFixture{
		oauth:       oauth,
		handler:     NewHTTPHandler(oauth, ""),
		jwks:        jwks,
		manipulator: manipulator,
		client:      client,
		app:         app,
		a3sIssuer:   a3sIssuer,
	}
}

func (f *tokenExchangeFixture) oauthIssuer() string {
	return f.oauth.issuerForNamespace("/")
}

// mintSubjectToken signs a token the way a3s would, so the exchange sees a
// realistic subject token rather than a hand-built claim set.
func (f *tokenExchangeFixture) mintSubjectToken(
	t *testing.T,
	issuer string,
	audience string,
	customize func(*token.IdentityToken),
) string {
	t.Helper()

	idt := token.NewIdentityToken(token.Source{Type: "OIDC", Namespace: "/", Name: "corp"})
	idt.Identity = []string{"email=user@example.com"}
	idt.OAuthApplication = token.OAuthApplication{ID: f.app.ID, Namespace: f.app.Namespace, Name: f.app.Name}
	idt.OAuthClient = token.OAuthClient{ClientID: f.client.ClientID, Namespace: f.client.Namespace}
	idt.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(time.Hour))

	if customize != nil {
		customize(idt)
	}

	key := f.jwks.GetLastWithPrivate()
	signed, err := idt.JWT(key.PrivateKey(), key.KID, issuer, jwt.ClaimStrings{audience}, idt.ExpiresAt.Time, nil)
	if err != nil {
		t.Fatalf("JWT() error = %v", err)
	}

	return signed
}

type tokenEndpointResponse struct {
	status  int
	body    string
	payload map[string]any
}

func (f *tokenExchangeFixture) exchange(t *testing.T, form url.Values) tokenEndpointResponse {
	t.Helper()

	return f.post(t, form, true)
}

// exchangeAnonymously posts a token request identifying no client at all,
// which the token-exchange grant accepts.
func (f *tokenExchangeFixture) exchangeAnonymously(t *testing.T, form url.Values) tokenEndpointResponse {
	t.Helper()

	return f.post(t, form, false)
}

func (f *tokenExchangeFixture) post(t *testing.T, form url.Values, authenticated bool) tokenEndpointResponse {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authenticated {
		request.SetBasicAuth(f.client.ClientID, f.client.ClientSecret)
	}

	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)

	payload := map[string]any{}
	if err := jsonNewDecoder(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response JSON: %v (%s)", err, recorder.Body.String())
	}

	return tokenEndpointResponse{
		status:  recorder.Code,
		body:    recorder.Body.String(),
		payload: payload,
	}
}

func assertClaim(t *testing.T, claims []string, want string) {
	t.Helper()

	for _, claim := range claims {
		if claim == want {
			return
		}
	}

	t.Fatalf("claims %v missing %q", claims, want)
}

func countClaimsWithPrefix(claims []string, prefix string) int {
	var count int
	for _, claim := range claims {
		if strings.HasPrefix(claim, prefix) {
			count++
		}
	}

	return count
}
