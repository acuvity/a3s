package mtlsissuer

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/karlseguin/ccache/v3"
)

var entraAccessTokenCache *ccache.Cache[string]

func init() {
	entraAccessTokenCache = ccache.New(ccache.Configure[string]().MaxSize(1024))
}

func handleEntraAutologin(iss *mtlsIssuer, cert *x509.Certificate) error {

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	rtoken := struct {
		AccessToken string `json:"access_token"`
	}{}

	// Step 1: get a client access token (client here is us), from net or cache
	ckey := fmt.Sprintf(
		"%s:%s:%s",
		&iss.source.EntraApplicationCredentials.ClientID,
		&iss.source.EntraApplicationCredentials.ClientSecret,
		&iss.source.EntraApplicationCredentials.ClientTenantID,
	)
	if item := entraAccessTokenCache.Get(ckey); item != nil && !item.Expired() {

		rtoken.AccessToken = item.Value()

	} else {

		form := url.Values{
			"client_id":     {iss.source.EntraApplicationCredentials.ClientID},
			"client_secret": {iss.source.EntraApplicationCredentials.ClientSecret},
			"scope":         {"https://graph.microsoft.com/.default"},
			"grant_type":    {"client_credentials"},
		}

		r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", &iss.source.EntraApplicationCredentials.ClientTenantID), strings.NewReader(form.Encode()))
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

		entraAccessTokenCache.Set(ckey, rtoken.AccessToken, 30*time.Minute)
	}

	// Extract the app id from the token.
	cls := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(rtoken.AccessToken, &cls); err != nil {
		return fmt.Errorf("unable to extract appid (oid) from access token claims: %w", err)
	}
	appID := cls["oid"]

	// Step 2: now we have a client token, we will query the user info
	principalName, err := getPrincipalName(iss, cert)
	if err != nil {
		return fmt.Errorf("unable to retrieve principal name from certificate: %w", err)
	}

	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", principalName), nil)
	if err != nil {
		return fmt.Errorf("unable to create request to retrieve use info: %w", err)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp2, err := client.Do(r)
	if err != nil {
		return fmt.Errorf("unable to send request to retrieve user id: %w", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code returned from request to retrieve user id: %s", resp2.Status)
	}

	ruser := struct {
		EMail             string `json:"mail"`
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		UserPrincipalName string `json:"userPrincipalName"`
	}{}

	dec := json.NewDecoder(resp2.Body)
	if err := dec.Decode(&ruser); err != nil {
		return fmt.Errorf("unable to decode user id:  %w", err)
	}

	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("nameid=%s", ruser.ID))

	// Step 3: finally we get the list group the user is a member of
	if r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf/microsoft.graph.group?$select=displayName", ruser.ID), nil); err != nil {
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

	rmember := struct {
		Values []struct {
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}{}

	dec = json.NewDecoder(resp3.Body)
	if err := dec.Decode(&rmember); err != nil {
		return fmt.Errorf("unable to decode user groups:  %w", err)
	}

	// Step 4: Retrieve all roles for the app and mapp them
	if r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals(appId='%s')?$select=id,displayName,appRoles", &iss.source.EntraApplicationCredentials.ClientID), nil); err != nil {
		return fmt.Errorf("unable to create request to retrieve app roles: %w", err)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp4, err := client.Do(r)
	if err != nil {
		return fmt.Errorf("unable to send request to retrieve app roles: %w", err)
	}
	defer func() { _ = resp4.Body.Close() }()

	if resp4.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code returned from request to retrieve app roles: %s", resp4.Status)
	}

	appRoles := struct {
		AppRoles []struct {
			ID   string `json:"id"`
			Name string `json:"value"`
		} `json:"appRoles"`
	}{}

	dec = json.NewDecoder(resp4.Body)
	if err := dec.Decode(&appRoles); err != nil {
		return fmt.Errorf("unable to decode app roles:  %w", err)
	}

	roleMap := make(map[string]string, len(appRoles.AppRoles))
	for _, r := range appRoles.AppRoles {
		roleMap[r.ID] = r.Name
	}

	// Step 5: Retrieve the user app role and map names
	if r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/appRoleAssignments?$filter=resourceId%%20eq%%20%s&$count=true", ruser.ID, appID), nil); err != nil {
		return fmt.Errorf("unable to create request to retrieve app role assignment of user: %w", err)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.AccessToken},
	}

	resp5, err := client.Do(r)
	if err != nil {
		return fmt.Errorf("unable to send request to retrieve app role assignments: %w", err)
	}
	defer func() { _ = resp5.Body.Close() }()

	if resp5.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code returned from request to retrieve app role assignments: %s", resp5.Status)
	}

	rmaprole := struct {
		Values []struct {
			AppRoleID     string `json:"appRoleId"`
			PrincipalType string `json:"principalType"`
		} `json:"value"`
	}{}

	dec = json.NewDecoder(resp5.Body)
	if err := dec.Decode(&rmaprole); err != nil {
		return fmt.Errorf("unable to decode app role assignments: %w", err)
	}

	// Final Step: populate the claims
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("displayname=%s", ruser.DisplayName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("oid=%s", ruser.ID))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("tenantid=%s", &iss.source.EntraApplicationCredentials.ClientTenantID))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("givenname=%s", ruser.GivenName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("email=%s", ruser.EMail))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("name=%s", ruser.UserPrincipalName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("surname=%s", ruser.Surname))

	for _, v := range rmember.Values {

		if v.DisplayName == "" {
			continue
		}

		iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("group=%s", v.DisplayName))
	}

	for _, m := range rmaprole.Values {

		n, ok := roleMap[m.AppRoleID]
		if !ok {
			continue
		}

		iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("app:role=%s", n))
	}

	return nil
}
