package okta

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/karlseguin/ccache/v3"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/tg/tglib"
)

type Manager struct {
	client       *http.Client
	requestMaker netsafe.RequestMaker
	tokenCache   *ccache.Cache[*AccessToken]
}

func NewEntraManager(client *http.Client, requestMaker netsafe.RequestMaker) *Manager {

	return &Manager{
		tokenCache:   ccache.New(ccache.Configure[*AccessToken]().MaxSize(1024)),
		client:       client,
		requestMaker: requestMaker,
	}
}

func (m *Manager) GetAccessToken(ctx context.Context, creds *api.MTLSSourceOkta) (*AccessToken, error) {

	if creds == nil {
		return nil, elemental.NewError("Invalid MTLS source", "No oktaApplicationCredentials set", "a3s:okta", http.StatusInternalServerError)
	}

	block, _ := pem.Decode([]byte(creds.PrivateKey))
	if block == nil {
		return nil, elemental.NewError("Invalid Okta credential private key", "Unable to decode PEM", "a3s:okta", http.StatusInternalServerError)
	}

	pk, err := tglib.PEMToKey(block)
	if err != nil {
		return nil, elemental.NewError("Invalid Okta credential private key", fmt.Sprintf("Unable to parse private key: %s", err), "a3s:okta", http.StatusInternalServerError)
	}

	domain := "https://" + strings.TrimRight(strings.TrimPrefix(strings.TrimSpace(creds.Domain), "https://"), "/")
	tokenURL := fmt.Sprintf("%s/oauth2/v1/token", domain)
	claims := jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{tokenURL},
		Subject:   creds.ClientID,
		Issuer:    creds.ClientID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	t.Header["kid"] = creds.KID
	jwtString, err := t.SignedString(pk)
	if err != nil {
		return nil, elemental.NewError("Unable to generate assertion JWT", err.Error(), "a3s:okta", http.StatusInternalServerError)
	}

	ckey := fmt.Sprintf(
		"%s:%s:%s:%s",
		creds.ClientID,
		creds.Domain,
		creds.KID,
		creds.PrivateKey,
	)

	rtoken := &AccessToken{}

	if item := m.tokenCache.Get(ckey); item != nil && !item.Expired() {

		rtoken = item.Value()

	} else {

		form := url.Values{
			"grant_type":            {"client_credentials"},
			"scope":                 {"okta.users.read okta.groups.read"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {jwtString},
		}

		r, err := m.requestMaker(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, elemental.NewError("Unable to create oauth2 token request", err.Error(), "a3s:okta", http.StatusInternalServerError)
		}
		r.Header = http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}

		resp, err := m.client.Do(r)
		if err != nil {
			return nil, elemental.NewError("Unable to send request to retrieve client access token", err.Error(), "a3s:okta", http.StatusBadRequest)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			d, _ := io.ReadAll(resp.Body)
			return nil, elemental.NewError("Invalid status code returned from request to retrieve client access token", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:okta", http.StatusBadRequest)
		}

		// utils.PeekBody(resp)

		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&rtoken); err != nil {
			return nil, elemental.NewError("Unable to decode Okta client token", err.Error(), "a3s:okta", http.StatusBadRequest)
		}

		rtoken.Domain = domain

		m.tokenCache.Set(ckey, rtoken, 30*time.Minute)
	}

	return rtoken, nil
}

func (m *Manager) GetUser(ctx context.Context, rtoken *AccessToken, principalName string) (*User, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/users/%s", rtoken.Domain, principalName), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve user info", err.Error(), "a3s:okta", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve user info", err.Error(), "a3s:okta", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve user info", fmt.Sprintf("(%s): %s", resp.Status, string(d)), "a3s:okta", http.StatusBadRequest)
	}

	// utils.PeekBody(resp)

	ruser := &User{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(ruser); err != nil {
		return nil, elemental.NewError("Unable to decode user id", err.Error(), "a3s:okta", http.StatusBadRequest)
	}

	return ruser, nil
}

func (m *Manager) GetMembership(ctx context.Context, rtoken *AccessToken, ruser *User) ([]Membership, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/users/%s/groups", rtoken.Domain, ruser.Profile.Login), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve user groups", err.Error(), "a3s:okta", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve user groups", err.Error(), "a3s:okta", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve user groups", fmt.Sprintf("(%s): %s", resp.Status, string(d)), "a3s:okta", http.StatusBadRequest)
	}

	// utils.PeekBody(resp)

	rmember := []Membership{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&rmember); err != nil {
		return nil, elemental.NewError("Unable to decode user groups", err.Error(), "a3s:okta", http.StatusBadRequest)
	}

	return rmember, nil
}
