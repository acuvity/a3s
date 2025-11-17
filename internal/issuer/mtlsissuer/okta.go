package mtlsissuer

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"go.acuvity.ai/a3s/internal/idp/okta"
)

func handleOktaAutologin(iss *mtlsIssuer, cert *x509.Certificate, oktaManager *okta.Manager) error {

	oerr := makeErrMaker("okta")

	rtoken, err := oktaManager.GetAccessToken(iss.source.OktaApplicationCredentials)
	if err != nil {
		return err
	}

	// Step 2: now we have a client token, we will query the user info
	principalName, err := getPrincipalName(iss, cert)
	if err != nil {
		return oerr("Unable to retrieve principal name from client certificate", err.Error(), http.StatusBadRequest)
	}

	ruser, err := oktaManager.GetUser(rtoken, principalName)
	if err != nil {
		return err
	}

	if ruser.Status != "ACTIVE" {
		return oerr("Forbidden", fmt.Sprintf("User is not marked as active (status: '%s')", ruser.Status), http.StatusForbidden)
	}

	rmember, err := oktaManager.GetMembership(rtoken, ruser)
	if err != nil {
		return err
	}

	iss.token.Identity = appendClaim(iss.token.Identity, "domain", rtoken.Domain)
	iss.token.Identity = appendClaim(iss.token.Identity, "firstname", ruser.Profile.FirstName)
	iss.token.Identity = appendClaim(iss.token.Identity, "oid", ruser.ID)
	iss.token.Identity = appendClaim(iss.token.Identity, "lastname", ruser.Profile.LastName)
	iss.token.Identity = appendClaim(iss.token.Identity, "email", ruser.Profile.EMail)
	iss.token.Identity = appendClaim(iss.token.Identity, "login", ruser.Profile.Login)

	for _, v := range rmember {
		if v.Profile.Name == "" {
			continue
		}
		iss.token.Identity = appendClaim(iss.token.Identity, "group", v.Profile.Name)
	}

	return nil
}
