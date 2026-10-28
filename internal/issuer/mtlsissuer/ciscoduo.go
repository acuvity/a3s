package mtlsissuer

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.acuvity.ai/a3s/internal/idp/ciscoduo"
)

func handleCiscoDuoAutologin(ctx context.Context, iss *mtlsIssuer, cert *x509.Certificate, ciscoDuoManager *ciscoduo.Manager) error {

	cerr := makeErrMaker("ciscoduo")

	principalName, err := getPrincipalName(iss.source.PrincipalUserX509Field, cert)
	if err != nil {
		return cerr("Unable to retrieve principal name from client certificate", err.Error(), http.StatusBadRequest)
	}

	ruser, err := ciscoDuoManager.GetUser(ctx, iss.source.CiscoDuoApplicationCredentials, principalName)
	if err != nil {
		return err
	}

	if ruser.Status != ciscoduo.UserStatusActive && ruser.Status != ciscoduo.UserStatusBypass {
		return cerr("Forbidden", fmt.Sprintf("User is not marked as active or bypass (status: '%s')", ruser.Status), http.StatusForbidden)
	}

	rmember, err := ciscoDuoManager.GetMembership(ctx, iss.source.CiscoDuoApplicationCredentials, ruser)
	if err != nil {
		return err
	}

	// Disabling a group in Duo disables its members at that time. This is a
	// safety net for members whose own status would not reflect it, like a
	// member added after the group was disabled.
	for _, v := range rmember {
		if strings.EqualFold(v.Status, ciscoduo.GroupStatusDisabled) {
			return cerr("Forbidden", fmt.Sprintf("User is member of disabled group '%s'", v.Name), http.StatusForbidden)
		}
	}

	iss.token.Identity = appendClaim(iss.token.Identity, "oid", ruser.ID)
	iss.token.Identity = appendClaim(iss.token.Identity, "email", ruser.Email)
	iss.token.Identity = appendClaim(iss.token.Identity, "login", ruser.Username)
	iss.token.Identity = appendClaim(iss.token.Identity, "firstname", ruser.FirstName)
	iss.token.Identity = appendClaim(iss.token.Identity, "lastname", ruser.LastName)
	iss.token.Identity = appendClaim(iss.token.Identity, "displayname", ruser.RealName)

	// Bypass users are not required to complete Duo 2FA. This is exposed so
	// policies can decide whether to trust them, for instance with bypass=false.
	iss.token.Identity = appendClaim(iss.token.Identity, "bypass", strconv.FormatBool(ruser.Status == ciscoduo.UserStatusBypass))

	for _, v := range rmember {
		if v.Name == "" {
			continue
		}
		iss.token.Identity = appendClaim(iss.token.Identity, "group", v.Name)
	}

	return nil
}
