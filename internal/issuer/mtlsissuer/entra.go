package mtlsissuer

import (
	"context"
	"crypto/x509"
	"net/http"

	"go.acuvity.ai/a3s/internal/idp/entra"
	"go.acuvity.ai/elemental"
)

func handleEntraAutologin(ctx context.Context, iss *mtlsIssuer, cert *x509.Certificate, entraManager *entra.Manager) error {

	atoken, err := entraManager.GetAccessToken(ctx, iss.source.EntraApplicationCredentials)
	if err != nil {
		return err
	}

	principalName, err := getPrincipalName(iss, cert)
	if err != nil {
		return elemental.NewError("Unable to retrieve principal name from certificate", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	user, err := entraManager.GetUser(ctx, atoken, principalName)
	if err != nil {
		return err
	}

	membership, err := entraManager.GetMembership(ctx, atoken, user)
	if err != nil {
		return err
	}

	approles, err := entraManager.GetAppRoles(ctx, atoken, user)
	if err != nil {
		return err
	}

	userroles, err := entraManager.GetRoles(ctx, atoken, user)
	if err != nil {
		return err
	}

	// map the roles of the user with the name of the role
	roleMap := make(map[string]entra.AppRole, len(approles.AppRoles))
	for _, r := range approles.AppRoles {
		roleMap[r.ID] = r
	}

	// Final Step: populate the claims
	iss.token.Identity = appendClaim(iss.token.Identity, "tenantid", iss.source.EntraApplicationCredentials.ClientTenantID)
	iss.token.Identity = appendClaim(iss.token.Identity, "nameid", user.ID)
	iss.token.Identity = appendClaim(iss.token.Identity, "displayname", user.DisplayName)
	iss.token.Identity = appendClaim(iss.token.Identity, "oid", user.ID)
	iss.token.Identity = appendClaim(iss.token.Identity, "givenname", user.GivenName)
	iss.token.Identity = appendClaim(iss.token.Identity, "email", user.EMail)
	iss.token.Identity = appendClaim(iss.token.Identity, "name", user.UserPrincipalName)
	iss.token.Identity = appendClaim(iss.token.Identity, "surname", user.Surname)

	for _, v := range membership.Values {
		if v.DisplayName != "" {
			iss.token.Identity = appendClaim(iss.token.Identity, "group", v.DisplayName)
			iss.token.Identity = appendClaim(iss.token.Identity, "group:id", v.ID)
		}
	}

	for _, m := range userroles.Values {
		if n, ok := roleMap[m.AppRoleID]; ok {
			iss.token.Identity = appendClaim(iss.token.Identity, "app:role", n.Name)
			iss.token.Identity = appendClaim(iss.token.Identity, "app:role:id", n.ID)
		}
	}

	return nil
}
