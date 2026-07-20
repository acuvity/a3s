package google

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

// googleDirectoryScopes are the read-only Directory API scopes needed to look
// up users and their group memberships.
const googleDirectoryScopes = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly"

// googleTokenURL is the Google OAuth2 endpoint used to exchange a service
// account JWT assertion for an access token. It is a var so tests can point it
// at a local server.
var googleTokenURL = "https://oauth2.googleapis.com/token"

// googleDirectoryBaseURL is the base URL of the Google Workspace Directory API.
// It is a var so tests can point it at a local server.
var googleDirectoryBaseURL = "https://admin.googleapis.com"

type Manager struct {
	client       *http.Client
	requestMaker netsafe.RequestMaker
	tokenCache   *ccache.Cache[*AccessToken]
}

func NewManager(client *http.Client, requestMaker netsafe.RequestMaker) *Manager {

	return &Manager{
		tokenCache:   ccache.New(ccache.Configure[*AccessToken]().MaxSize(1024)),
		client:       client,
		requestMaker: requestMaker,
	}
}

func (m *Manager) GetAccessToken(ctx context.Context, creds *api.MTLSSourceGoogle) (*AccessToken, error) {

	if creds == nil {
		return nil, elemental.NewError("Invalid MTLS source", "No googleWorkspaceApplicationCredentials set", "a3s:google", http.StatusInternalServerError)
	}

	block, _ := pem.Decode([]byte(creds.PrivateKey))
	if block == nil {
		return nil, elemental.NewError("Invalid Google credential private key", "Unable to decode PEM", "a3s:google", http.StatusInternalServerError)
	}

	pk, err := tglib.PEMToKey(block)
	if err != nil {
		return nil, elemental.NewError("Invalid Google credential private key", fmt.Sprintf("Unable to parse private key: %s", err), "a3s:google", http.StatusInternalServerError)
	}

	now := time.Now()
	claims := assertionClaims{
		Scope: googleDirectoryScopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{googleTokenURL},
			Issuer:    creds.ClientEmail,
			Subject:   creds.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = creds.PrivateKeyID
	jwtString, err := t.SignedString(pk)
	if err != nil {
		return nil, elemental.NewError("Unable to generate assertion JWT", err.Error(), "a3s:google", http.StatusInternalServerError)
	}

	ckey := fmt.Sprintf(
		"%s:%s:%s:%s",
		creds.ClientEmail,
		creds.Subject,
		creds.PrivateKeyID,
		creds.PrivateKey,
	)

	rtoken := &AccessToken{}

	if item := m.tokenCache.Get(ckey); item != nil && !item.Expired() {

		rtoken = item.Value()

	} else {

		form := url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {jwtString},
		}

		r, err := m.requestMaker(ctx, http.MethodPost, googleTokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, elemental.NewError("Unable to create oauth2 token request", err.Error(), "a3s:google", http.StatusInternalServerError)
		}
		r.Header = http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}

		resp, err := m.client.Do(r)
		if err != nil {
			return nil, elemental.NewError("Unable to send request to retrieve client access token", err.Error(), "a3s:google", http.StatusBadRequest)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			d, _ := io.ReadAll(resp.Body)
			return nil, elemental.NewError("Invalid status code returned from request to retrieve client access token", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:google", http.StatusBadRequest)
		}

		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&rtoken); err != nil {
			return nil, elemental.NewError("Unable to decode Google client token", err.Error(), "a3s:google", http.StatusBadRequest)
		}

		m.tokenCache.Set(ckey, rtoken, 30*time.Minute)
	}

	return rtoken, nil
}

func (m *Manager) GetUser(ctx context.Context, rtoken *AccessToken, principalName string) (*User, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("%s/admin/directory/v1/users/%s", googleDirectoryBaseURL, principalName), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve user info", err.Error(), "a3s:google", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve user info", err.Error(), "a3s:google", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve user info", fmt.Sprintf("(%s): %s", resp.Status, string(d)), "a3s:google", http.StatusBadRequest)
	}

	ruser := &User{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(ruser); err != nil {
		return nil, elemental.NewError("Unable to decode user", err.Error(), "a3s:google", http.StatusBadRequest)
	}

	return ruser, nil
}

func (m *Manager) GetMembership(ctx context.Context, rtoken *AccessToken, ruser *User) ([]Membership, error) {

	rmember := []Membership{}
	pageToken := ""

	for {
		q := url.Values{
			"userKey":    {ruser.PrimaryEmail},
			"maxResults": {"200"},
		}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}

		next := fmt.Sprintf("%s/admin/directory/v1/groups?%s", googleDirectoryBaseURL, q.Encode())

		r, err := m.requestMaker(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, elemental.NewError("Unable to create request to retrieve user groups", err.Error(), "a3s:google", http.StatusBadRequest)
		}
		r.Header = http.Header{
			"Authorization": {"Bearer " + rtoken.AccessToken},
		}

		resp, err := m.client.Do(r)
		if err != nil {
			return nil, elemental.NewError("Unable to send request to retrieve user groups", err.Error(), "a3s:google", http.StatusBadRequest)
		}

		if resp.StatusCode != http.StatusOK {
			d, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, elemental.NewError("Invalid status code returned from request to retrieve user groups", fmt.Sprintf("(%s): %s", resp.Status, string(d)), "a3s:google", http.StatusBadRequest)
		}

		page := groupsResponse{}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			_ = resp.Body.Close()
			return nil, elemental.NewError("Unable to decode user groups", err.Error(), "a3s:google", http.StatusBadRequest)
		}
		_ = resp.Body.Close()

		rmember = append(rmember, page.Groups...)

		pageToken = page.NextPageToken
		if pageToken == "" {
			break
		}
	}

	return rmember, nil
}
