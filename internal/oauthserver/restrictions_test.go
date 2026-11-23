package oauthserver

import (
	"net/http"
	"reflect"
	"slices"
	"testing"

	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
)

// grantTokens redeems a code and returns the access and the refresh tokens.
func (f *tokenExchangeFixture) grantTokens(t *testing.T) (*token.IdentityToken, string) {
	t.Helper()

	response := f.redeemCode(t, f.codeFor(t, f.authorizeParams("profile"), []string{"sub=1234"}))
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	refreshToken, _ := response.payload["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("response missing refresh_token")
	}

	return f.accessToken(t, response), refreshToken
}

func (f *tokenExchangeFixture) accessToken(t *testing.T, response tokenEndpointResponse) *token.IdentityToken {
	t.Helper()

	raw, _ := response.payload["access_token"].(string)
	idt, err := token.Parse(raw, f.jwks, f.oauthIssuer(), f.app.Audience)
	if err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}

	return idt
}

func assertRestrictedTo(t *testing.T, idt *token.IdentityToken, namespace string, perms []string) {
	t.Helper()

	if idt.Restrictions == nil {
		t.Fatal("access token is not restricted")
	}
	if idt.Restrictions.Namespace != namespace {
		t.Errorf("restricted namespace = %q, want %q", idt.Restrictions.Namespace, namespace)
	}
	if !slices.Equal(idt.Restrictions.Permissions, perms) {
		t.Errorf("restricted permissions = %v, want %v", idt.Restrictions.Permissions, perms)
	}
}

func TestAuthorizationCodeGrantRestrictsTheAccessTokenToTheApplicationPermissions(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	fixture.app.Permissions = []string{"namespace:retrieve"}

	access, refreshToken := fixture.grantTokens(t)

	assertRestrictedTo(t, access, fixture.app.Namespace, []string{"namespace:retrieve"})

	refresh, err := token.Parse(refreshToken, fixture.jwks, fixture.oauthIssuer(), fixture.oauthIssuer())
	if err != nil {
		t.Fatalf("refresh token does not verify: %v", err)
	}
	if refresh.Restrictions != nil {
		t.Errorf("refresh token restrictions = %+v, want none", refresh.Restrictions)
	}
}

func TestRefreshTokenGrantAppliesTheCurrentApplicationPermissions(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	fixture.app.Permissions = []string{"namespace:retrieve"}

	_, refreshToken := fixture.grantTokens(t)

	// Widening them must apply too, which it could not if the refresh token
	// carried the previous ones.
	fixture.app.Permissions = []string{"namespace:retrieve,retrieve-many", "authorization:retrieve"}

	response := fixture.refresh(t, refreshToken, "")
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}

	assertRestrictedTo(t, fixture.accessToken(t, response), fixture.app.Namespace, fixture.app.Permissions)
}

func TestApplicationWithoutPermissionsDoesNotRestrictTheAccessTokens(t *testing.T) {
	fixture := newTokenExchangeFixture(t)

	access, refreshToken := fixture.grantTokens(t)
	if access.Restrictions != nil {
		t.Errorf("access token restrictions = %+v, want none", access.Restrictions)
	}

	response := fixture.refresh(t, refreshToken, "")
	if response.status != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d", response.status, response.body, http.StatusOK)
	}
	if r := fixture.accessToken(t, response).Restrictions; r != nil {
		t.Errorf("refreshed access token restrictions = %+v, want none", r)
	}
}

func TestSessionRestrictedOutsideOfTheApplicationIsRefused(t *testing.T) {
	fixture := newTokenExchangeFixture(t)
	fixture.app.Permissions = []string{"namespace:retrieve"}

	idt := token.NewIdentityToken(fixture.identitySource)
	idt.Restrictions = &permissions.Restrictions{Permissions: []string{"authorization:retrieve"}}

	if _, err := fixture.oauth.CompleteAuthorize(idt, &AuthorizeContext{}, fixture.client, fixture.app); err == nil {
		t.Fatal("CompleteAuthorize() succeeded, want a restrictions error")
	}
}

func TestIntersectRestrictions(t *testing.T) {
	app := permissions.Restrictions{Namespace: "/orgs/acme", Permissions: []string{"namespace:retrieve,retrieve-many"}}

	for _, test := range []struct {
		name    string
		session *permissions.Restrictions
		app     permissions.Restrictions
		want    *permissions.Restrictions
		wantErr bool
	}{
		{
			name: "unrestricted session and application",
		},
		{
			name: "unrestricted session",
			app:  app,
			want: &app,
		},
		{
			name:    "unrestricted application",
			session: &app,
			want:    &app,
		},
		{
			name:    "session narrower than the application",
			session: &permissions.Restrictions{Namespace: "/orgs/acme/team", Permissions: []string{"namespace:retrieve"}},
			app:     app,
			want:    &permissions.Restrictions{Namespace: "/orgs/acme/team", Permissions: []string{"namespace:retrieve"}},
		},
		{
			name:    "session wider than the application",
			session: &permissions.Restrictions{Namespace: "/orgs", Permissions: []string{"namespace:*"}},
			app:     app,
			want:    &app,
		},
		{
			name:    "session networks are kept",
			session: &permissions.Restrictions{Networks: []string{"10.0.0.0/8"}},
			app:     app,
			want:    &permissions.Restrictions{Namespace: "/orgs/acme", Permissions: app.Permissions, Networks: []string{"10.0.0.0/8"}},
		},
		{
			name:    "disjoint namespaces",
			session: &permissions.Restrictions{Namespace: "/orgs/other"},
			app:     app,
			wantErr: true,
		},
		{
			name:    "overlapping permissions",
			session: &permissions.Restrictions{Permissions: []string{"namespace:retrieve", "authorization:retrieve"}},
			app:     app,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := intersectRestrictions(test.session, test.app)
			if (err != nil) != test.wantErr {
				t.Fatalf("intersectRestrictions() error = %v, want error %t", err, test.wantErr)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("intersectRestrictions() = %+v, want %+v", got, test.want)
			}
		})
	}
}
