package mtlsissuer

import (
	"crypto/x509"
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
	"go.acuvity.ai/tg/tglib"
)

var oktaAccessTokenCache *ccache.Cache[string]

func init() {
	oktaAccessTokenCache = ccache.New(ccache.Configure[string]().MaxSize(1024))
}

func handleOktaAutologin(iss *mtlsIssuer, cert *x509.Certificate) error {

	oerr := makeErrMaker("okta")

	creds := iss.source.OktaApplicationCredentials
	if creds == nil {
		return oerr("Invalid MTLS source", "No oktaApplicationCredentials set", http.StatusInternalServerError)
	}

	block, _ := pem.Decode([]byte(creds.PrivateKey))
	if block == nil {
		return oerr("Invalid Okta credential private key", "Unable to decode PEM", http.StatusInternalServerError)
	}

	pk, err := tglib.PEMToKey(block)
	if err != nil {
		return oerr("Invalid Okta credential private key", fmt.Sprintf("Unable to parse private key: %s", err), http.StatusInternalServerError)
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
		return oerr("Unable to generate assertion JWT", err.Error(), http.StatusInternalServerError)
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
		creds.ClientID,
		creds.Domain,
		creds.KID,
		creds.PrivateKey,
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
			return oerr("Unable to create oauth2 token request", err.Error(), http.StatusInternalServerError)
		}
		r.Header = http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}

		resp1, err := client.Do(r)
		if err != nil {
			return oerr("Unable to send request to retrieve client access token", err.Error(), http.StatusBadRequest)
		}
		defer func() { _ = resp1.Body.Close() }()

		if resp1.StatusCode != http.StatusOK {
			d, _ := io.ReadAll(resp1.Body)
			return oerr("Invalid status code returned from request to retrieve client access token", fmt.Sprintf("(%s) %s", resp1.Status, string(d)), http.StatusBadRequest)
		}

		dec := json.NewDecoder(resp1.Body)
		if err := dec.Decode(&rtoken); err != nil {
			return oerr("Unable to decode Okta client token", err.Error(), http.StatusBadRequest)
		}

		oktaAccessTokenCache.Set(ckey, rtoken.AccessToken, 30*time.Minute)
	}

	// Step 2: now we have a client token, we will query the user info
	principalName, err := getPrincipalName(iss, cert)
	if err != nil {
		return oerr("Unable to retrieve principal name from client certificate", err.Error(), http.StatusBadRequest)
	}

	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/users/%s", domain, principalName), nil)
	if err != nil {
		return oerr("Unable to create request to retrieve user info", err.Error(), http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp2, err := client.Do(r)
	if err != nil {
		return oerr("Unable to send request to retrieve user info", err.Error(), http.StatusBadRequest)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp2.Body)
		return oerr("Invalid status code returned from request to retrieve user info", fmt.Sprintf("(%s): %s", resp2.Status, string(d)), http.StatusBadRequest)
	}

	// Debug code
	// data, _ := io.ReadAll(resp2.Body)
	// fmt.Println(string(data))
	// resp2.Body = io.NopCloser(bytes.NewBuffer(data))

	ruser := struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Profile struct {
			EMail     string `json:"email"`
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
			Login     string `json:"login"`
		} `json:"profile"`
	}{}

	dec := json.NewDecoder(resp2.Body)
	if err := dec.Decode(&ruser); err != nil {
		return oerr(
			"Unable to decode user id",
			err.Error(),

			http.StatusBadRequest,
		)
	}

	if ruser.Status != "ACTIVE" {
		return oerr("Forbidden", fmt.Sprintf("User is not marked as active (status: '%s')", ruser.Status), http.StatusForbidden)
	}

	// Step 3: finally we get the list group the user is a member of
	if r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/users/%s/groups", domain, principalName), nil); err != nil {
		return oerr("Unable to create request to retrieve user groups", err.Error(), http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp3, err := client.Do(r)
	if err != nil {
		return oerr("Unable to send request to retrieve user groups", err.Error(), http.StatusBadRequest)
	}
	defer func() { _ = resp3.Body.Close() }()

	if resp3.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp3.Body)
		return oerr("Invalid status code returned from request to retrieve user groups", fmt.Sprintf("(%s): %s", resp3.Status, string(d)), http.StatusBadRequest)
	}

	rmember := []struct {
		ID      string `json:"id"`
		Profile struct {
			Name string `json:"name"`
		} `json:"profile"`
	}{}

	dec = json.NewDecoder(resp3.Body)
	if err := dec.Decode(&rmember); err != nil {
		return oerr("Unable to decode user groups", err.Error(), http.StatusBadRequest)
	}

	// Final Step: populate the claims
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("domain=%s", creds.Domain))
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
