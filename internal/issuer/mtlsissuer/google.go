package mtlsissuer

import (
	"context"
	"crypto/x509"
	"net/http"

	"go.acuvity.ai/a3s/internal/idp/google"
)

func handleGoogleAutologin(ctx context.Context, iss *mtlsIssuer, cert *x509.Certificate, googleManager *google.Manager) error {

	gerr := makeErrMaker("google")

	rtoken, err := googleManager.GetAccessToken(ctx, iss.source.GoogleWorkspaceApplicationCredentials)
	if err != nil {
		return err
	}

	principalName, err := getPrincipalName(iss.source.PrincipalUserX509Field, cert)
	if err != nil {
		return gerr("Unable to retrieve principal name from client certificate", err.Error(), http.StatusBadRequest)
	}

	ruser, err := googleManager.GetUser(ctx, rtoken, principalName)
	if err != nil {
		return err
	}

	if ruser.Suspended {
		return gerr("Forbidden", "User is suspended", http.StatusForbidden)
	}

	rmember, err := googleManager.GetMembership(ctx, rtoken, ruser)
	if err != nil {
		return err
	}

	iss.token.Identity = appendClaim(iss.token.Identity, "oid", ruser.ID)
	iss.token.Identity = appendClaim(iss.token.Identity, "email", ruser.PrimaryEmail)
	iss.token.Identity = appendClaim(iss.token.Identity, "firstname", ruser.Name.GivenName)
	iss.token.Identity = appendClaim(iss.token.Identity, "lastname", ruser.Name.FamilyName)
	iss.token.Identity = appendClaim(iss.token.Identity, "displayname", ruser.Name.FullName)

	for _, v := range rmember {
		if v.Name == "" {
			continue
		}
		iss.token.Identity = appendClaim(iss.token.Identity, "group", v.Name)
	}

	return nil
}
