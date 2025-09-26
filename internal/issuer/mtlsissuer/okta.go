package mtlsissuer

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/karlseguin/ccache/v3"
	"go.acuvity.ai/tg/tglib"
)

var oktaAccessTokenCache *ccache.Cache[string]

func init() {
	oktaAccessTokenCache = ccache.New(ccache.Configure[string]().MaxSize(1024))
}

func handleOktaAutologin(iss *mtlsIssuer, cert *x509.Certificate) error {

	block, _ := pem.Decode([]byte(iss.source.OktaApplicationCredentials.PrivateKey))
	pk, err := tglib.PEMToKey(block)
	if err != nil {
		return fmt.Errorf("unable to decode source private key: %w", err)
	}

	domain := "https://" + strings.TrimRight(strings.TrimPrefix(strings.TrimSpace(iss.source.OktaApplicationCredentials.Domain), "https://"), "/")
	tokenURL := fmt.Sprintf("%s/oauth2/v1/token", domain)
	claims := jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{tokenURL},
		Subject:   iss.source.OktaApplicationCredentials.ClientID,
		Issuer:    iss.source.OktaApplicationCredentials.ClientID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	t.Header["kid"] = iss.source.OktaApplicationCredentials.KID
	jwtString, err := t.SignedString(pk)
	if err != nil {
		return fmt.Errorf("unable to generate assertion jwt: %w", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	rtoken := struct {
		AccessToken string `json:"access_token"`
	}{}

	// Step 1: get a client access token (client here is us), from net or cache
	ckey := fmt.Sprintf(
		"%s:%s:%s:%s",
		iss.source.OktaApplicationCredentials.ClientID,
		iss.source.OktaApplicationCredentials.Domain,
		iss.source.OktaApplicationCredentials.KID,
		iss.source.OktaApplicationCredentials.PrivateKey,
	)

	if item := oktaAccessTokenCache.Get(ckey); item != nil && !item.Expired() {

		rtoken.AccessToken = item.Value()

	} else {

		form := url.Values{
			"grant_type":            {"client_credentials"},
			"scope":                 {"okta.users.read okta.groups.read"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {jwtString},
		}

		r, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("unable to create oauth2 client token request: %w", err)
		}
		r.Header = http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}

		resp1, err := client.Do(r)
		if err != nil {
			return fmt.Errorf("unable to send request to retrieve client access token: %w", err)
		}
		defer func() { _ = resp1.Body.Close() }()

		if resp1.StatusCode != http.StatusOK {
			return fmt.Errorf("invalid status code returned from request to retrieve client access token: %s", resp1.Status)
		}

		dec := json.NewDecoder(resp1.Body)
		if err := dec.Decode(&rtoken); err != nil {
			return fmt.Errorf("unable to decode client access token:  %w", err)
		}

		oktaAccessTokenCache.Set(ckey, rtoken.AccessToken, 30*time.Minute)
	}

	// Step 2: now we have a client token, we will query the user info
	principalName, err := getPrincipalName(iss, cert)
	if err != nil {
		return fmt.Errorf("unable to retrieve principal name from certificate: %w", err)
	}

	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/users/%s", domain, principalName), nil)
	if err != nil {
		return fmt.Errorf("unable to create request to retrieve user info: %w", err)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp2, err := client.Do(r)
	if err != nil {
		return fmt.Errorf("unable to send request to retrieve user info: %w", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code returned from request to retrieve user info: %s", resp2.Status)
	}

	ruser := struct {
		ID      string `json:"id"`
		Profile struct {
			EMail     string `json:"email"`
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
			Login     string `json:"login"`
		} `json:"profile"`
	}{}

	dec := json.NewDecoder(resp2.Body)
	if err := dec.Decode(&ruser); err != nil {
		return fmt.Errorf("unable to decode user id:  %w", err)
	}

	// Step 3: finally we get the list group the user is a member of
	if r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/users/%s/groups", domain, principalName), nil); err != nil {
		return fmt.Errorf("unable to create request to retrieve groups of user: %w", err)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp3, err := client.Do(r)
	if err != nil {
		return fmt.Errorf("unable to send request to retrieve user groups: %w", err)
	}
	defer func() { _ = resp3.Body.Close() }()

	if resp3.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code returned from request to retrieve user groups: %s", resp3.Status)
	}

	rmember := []struct {
		ID      string `json:"id"`
		Profile struct {
			Name string `json:"name"`
		} `json:"profile"`
	}{}

	dec = json.NewDecoder(resp3.Body)
	if err := dec.Decode(&rmember); err != nil {
		return fmt.Errorf("unable to decode user groups:  %w", err)
	}

	// Final Step: populate the claims
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("domain=%s", iss.source.OktaApplicationCredentials.Domain))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("firstname=%s", ruser.Profile.FirstName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("oid=%s", ruser.ID))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("lastname=%s", ruser.Profile.LastName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("email=%s", ruser.Profile.EMail))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("login=%s", ruser.Profile.Login))

	for _, v := range rmember {
		if v.Profile.Name == "" {
			continue
		}
		iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("group=%s", v.Profile.Name))
	}

	return nil
}
