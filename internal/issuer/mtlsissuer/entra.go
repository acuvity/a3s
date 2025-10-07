package mtlsissuer

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"go.acuvity.ai/a3s/internal/idp/entra"
	"go.acuvity.ai/elemental"
)

func handleEntraAutologin(iss *mtlsIssuer, cert *x509.Certificate, entraManager *entra.Manager) error {

	atoken, err := entraManager.GetAccessToken(iss.source.EntraApplicationCredentials)
	if err != nil {
		return err
	}

	principalName, err := getPrincipalName(iss, cert)
	if err != nil {
		return elemental.NewError("Unable to retrieve principal name from certificate", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	user, err := entraManager.GetUser(atoken, principalName)
	if err != nil {
		return err
	}

	membership, err := entraManager.GetMembership(atoken, user)
	if err != nil {
		return err
	}

	approles, err := entraManager.GetAppRoles(atoken, user)
	if err != nil {
		return err
	}

	userroles, err := entraManager.GetRoles(atoken, user)
	if err != nil {
		return err
	}

	// map the roles of the user with the name of the role
	roleMap := make(map[string]entra.AppRole, len(approles.AppRoles))
	for _, r := range approles.AppRoles {
		roleMap[r.ID] = r
	}

	// Final Step: populate the claims
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("tenantid=%s", iss.source.EntraApplicationCredentials.ClientTenantID))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("nameid=%s", user.ID))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("displayname=%s", user.DisplayName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("oid=%s", user.ID))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("givenname=%s", user.GivenName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("email=%s", user.EMail))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("name=%s", user.UserPrincipalName))
	iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("surname=%s", user.Surname))

	for _, v := range membership.Values {
		if v.DisplayName != "" {
			iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("group=%s", v.DisplayName))
			iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("group:id=%s", v.ID))
		}
	}

	for _, m := range userroles.Values {
		if n, ok := roleMap[m.AppRoleID]; ok {
			iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("app:role=%s", n.Name))
			iss.token.Identity = append(iss.token.Identity, fmt.Sprintf("app:role:id=%s", n.ID))
		}
	}

	return nil
}
