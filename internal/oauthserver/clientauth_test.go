package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// postTokenAs posts a token request authenticating with the given Basic
// credentials, sent verbatim so a test controls their exact encoding.
//
// The grant type is deliberately unsupported: client authentication runs
// before any grant is dispatched, so "unsupported_grant_type" means the
// credentials were accepted and "invalid_client" means they were not.
func (f *tokenExchangeFixture) postTokenAs(t *testing.T, userid string, password string) tokenEndpointResponse {
	t.Helper()

	form := url.Values{"grant_type": {"urn:test:unsupported"}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(userid, password)

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

func TestTokenEndpointAuthenticatesClientIDHoldingTheBasicSeparator(t *testing.T) {
	// HTTP Basic splits on the first colon, so an identifier containing one
	// only survives the round trip percent-encoded.
	fixture := newTokenExchangeFixture(t)
	fixture.client.ClientID = "client:id:with:colons"

	encoded := fixture.postTokenAs(t, url.QueryEscape(fixture.client.ClientID), fixture.client.ClientSecret)
	if got := encoded.payload["error"]; got != "unsupported_grant_type" {
		t.Errorf("percent-encoded: error = %#v, want %q (%s)", got, "unsupported_grant_type", encoded.body)
	}

	// Sent raw, neither half of the credential is what the client meant, and
	// a3s refuses rather than guessing where the identifier ended.
	raw := fixture.postTokenAs(t, fixture.client.ClientID, fixture.client.ClientSecret)
	if got := raw.payload["error"]; got != "invalid_client" {
		t.Errorf("raw: error = %#v, want %q (%s)", got, "invalid_client", raw.body)
	}
}

func TestTokenEndpointLeavesTheBasicSecretUndecoded(t *testing.T) {
	// Secrets are admin-supplied, so one holding a percent escape must keep
	// authenticating as the literal it was stored as.
	fixture := newTokenExchangeFixture(t)
	fixture.client.ClientSecret = "p%41ss+word"

	response := fixture.postTokenAs(t, fixture.client.ClientID, fixture.client.ClientSecret)

	if got := response.payload["error"]; got != "unsupported_grant_type" {
		t.Errorf("error = %#v, want %q (%s)", got, "unsupported_grant_type", response.body)
	}
}
