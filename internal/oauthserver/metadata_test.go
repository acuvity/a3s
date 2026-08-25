package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/go-zoo/bone"
)

func TestOpenIDConfigurationServedOnBothDiscoveryPaths(t *testing.T) {
	// Both the RFC 8414 prefixed form and the OpenID Connect Discovery 1.0
	// suffixed form must describe the same authorization server.
	for _, path := range []string{
		"/.well-known/openid-configuration/oauth",
		"/oauth/.well-known/openid-configuration",
	} {
		t.Run(path, func(t *testing.T) {
			handler := newOAuthHTTPHandlerForTest(t)

			request := httptest.NewRequest(http.MethodGet, path, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			assertOAuthJSONField(t, recorder, http.StatusOK, "issuer", "https://issuer.example/oauth")
			assertOAuthJSONField(t, recorder, http.StatusOK, "authorization_endpoint", "https://issuer.example/oauth/authorize")
			assertOAuthJSONField(t, recorder, http.StatusOK, "token_endpoint", "https://issuer.example/oauth/token")
			assertOAuthJSONField(t, recorder, http.StatusOK, "jwks_uri", "https://issuer.example/.well-known/jwks.json")
			assertOAuthJSONField(t, recorder, http.StatusOK, "userinfo_endpoint", "https://issuer.example/oauth/userinfo")
			assertOAuthJSONField(t, recorder, http.StatusOK, "response_types_supported", []any{"code"})
			assertOAuthJSONField(t, recorder, http.StatusOK, "grant_types_supported", []any{
				"authorization_code",
				"urn:ietf:params:oauth:grant-type:token-exchange",
			})
			assertOAuthJSONField(t, recorder, http.StatusOK, "code_challenge_methods_supported", []any{"S256"})
			assertOAuthJSONField(t, recorder, http.StatusOK, "subject_types_supported", []any{"public"})
			assertOAuthJSONField(t, recorder, http.StatusOK, "id_token_signing_alg_values_supported", []any{"ES256"})
		})
	}
}

func TestOpenIDConfigurationIgnoresPathsOutsideTheIssuer(t *testing.T) {
	// The appended form is recognised by its issuer prefix, not by its
	// well-known suffix alone.
	handler := newOAuthHTTPHandlerForTest(t)

	request := httptest.NewRequest(http.MethodGet, "/somewhere/else/.well-known/openid-configuration", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

func TestOpenIDConfigurationRejectsNonGET(t *testing.T) {
	handler := newOAuthHTTPHandlerForTest(t)

	request := httptest.NewRequest(http.MethodPost, "/oauth/.well-known/openid-configuration", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assertOAuthJSONField(t, recorder, http.StatusMethodNotAllowed, "error", "invalid_request")
	if got := recorder.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want %q", got, http.MethodGet)
	}
}

func TestOAuthRoutesIncludeDiscoveryEndpoints(t *testing.T) {
	handler := newOAuthHTTPHandlerForTest(t)

	routes := handler.routes()
	for _, want := range []string{
		"/.well-known/oauth-authorization-server/oauth",
		"/.well-known/oauth-authorization-server/oauth/:namespace",
		"/.well-known/openid-configuration/oauth",
		"/.well-known/openid-configuration/oauth/:namespace",
		"/oauth/.well-known/openid-configuration",
		"/oauth/:namespace/.well-known/openid-configuration",
	} {
		if !slices.Contains(routes, want) {
			t.Errorf("routes() missing %q, got %v", want, routes)
		}
	}
}

// TestOpenIDConfigurationRoutingThroughMux checks the discovery paths against a
// real router, since the namespaced forms take their namespace from a path
// parameter and the root forms must not be captured by the namespaced OAuth
// patterns.
func TestOpenIDConfigurationRoutingThroughMux(t *testing.T) {
	handler := newOAuthHTTPHandlerForTest(t)

	mux := bone.New()
	for _, route := range handler.routes() {
		mux.Handle(route, http.HandlerFunc(handler.ServeHTTP))
	}

	encodedNamespace := encodeNamespace("/team")

	for _, test := range []struct {
		path       string
		wantIssuer string
	}{
		{
			path:       "/oauth/.well-known/openid-configuration",
			wantIssuer: "https://issuer.example/oauth",
		},
		{
			path:       "/.well-known/openid-configuration/oauth",
			wantIssuer: "https://issuer.example/oauth",
		},
		{
			path:       "/oauth/" + encodedNamespace + "/.well-known/openid-configuration",
			wantIssuer: "https://issuer.example/oauth/" + encodedNamespace,
		},
		{
			path:       "/.well-known/openid-configuration/oauth/" + encodedNamespace,
			wantIssuer: "https://issuer.example/oauth/" + encodedNamespace,
		},
	} {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)

			assertOAuthJSONField(t, recorder, http.StatusOK, "issuer", test.wantIssuer)
			assertOAuthJSONField(t, recorder, http.StatusOK, "subject_types_supported", []any{"public"})
		})
	}

	// The discovery routes must not shadow the protocol endpoints.
	request := httptest.NewRequest(http.MethodGet, "/oauth/"+encodedNamespace+"/token", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)

	assertOAuthJSONField(t, recorder, http.StatusMethodNotAllowed, "error_description", "token endpoint only accepts POST")
}
