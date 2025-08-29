package mtlsissuer

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.acuvity.ai/a3s/pkgs/api"
)

func handleEntraAutologin(iss *mtlsIssuer, cert *x509.Certificate) error {

	client := &http.Client{}

	// Step 1: get a client access token (client here is us)
	form := url.Values{
		"client_id":     {iss.source.ClientID},
		"client_secret": {iss.source.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}

	r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", iss.source.ClientTenantID), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("unable to retrieve user data: %w", err)
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
		return fmt.Errorf("unable to send request to retrieve client access token: %s", resp1.Status)
	}

	rtoken := struct {
		AccessToken string `json:"access_token"`
	}{}

	dec := json.NewDecoder(resp1.Body)
	if err := dec.Decode(&rtoken); err != nil {
		return fmt.Errorf("unable to decode client access token:  %w", err)
	}

	// Step 2: now we have a client token, we will query the user info
	principalName := ""

	switch iss.source.PrincipalUserX509Field {

	case api.MTLSSourcePrincipalUserX509FieldCommonName:
		principalName = cert.Subject.CommonName

	case api.MTLSSourcePrincipalUserX509FieldEmail:
		if len(cert.EmailAddresses) > 0 {
			principalName = cert.EmailAddresses[0]
		} else {
			return fmt.Errorf("unable to find any email addresses in the user certificate")
		}
	}

	if r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", principalName), nil); err != nil {
		return fmt.Errorf("unable to retrieve user data: %w", err)
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
		return fmt.Errorf("unable to send request to retrieve user id: %s", resp2.Status)
	}

	ruser := struct {
		EMail             string `json:"mail"`
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		UserPrincipalName string `json:"userPrincipalName"`
	}{}

	dec = json.NewDecoder(resp2.Body)
	if err := dec.Decode(&ruser); err != nil {
		return fmt.Errorf("unable to decode user id:  %w", err)
	}

	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("nameid=%s", ruser.ID))

	// Step 3: finally we get the list group the user is a member of
	if r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf/microsoft.graph.group?$select=displayName", ruser.ID), nil); err != nil {
		return fmt.Errorf("unable to retrieve user groups: %w", err)
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
		return fmt.Errorf("unable to send request to retrieve user groups: %s", resp3.Status)
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

	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("displayname=%s", ruser.DisplayName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("oid=%s", ruser.ID))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("tenantid=%s", iss.source.ClientTenantID))
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

	return nil
}
