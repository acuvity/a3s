package usernamespace

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.aporeto.io/a3s/pkgs/api"
	"go.aporeto.io/manipulate"
)

// This file has code to create a user namespace. Needs to be converted to generic a3s capability.

// System constants
const (
	namespaceUsers    = "/users"
	emailClaimPrefix  = "email="
	systemClaimPrefix = "@"
)

// getEmailFromClaims gets the email from claims. returns false if not found.
func getEmailFromClaims(claims []string) (string, bool) {
	for i := 0; i < len(claims); i++ {
		if strings.HasPrefix(claims[i], emailClaimPrefix) {
			email := strings.TrimPrefix(claims[i], emailClaimPrefix)
			return email, true
		}
	}
	return "", false
}

// getAuthzClaims returns subset of claims which will be used as a subject for authz.
func getAuthzClaims(claims []string) []string {
	authzClaims := []string{}
	for i := 0; i < len(claims); i++ {
		if strings.HasPrefix(claims[i], systemClaimPrefix) {
			authzClaims = append(authzClaims, claims[i])
		} else if strings.HasPrefix(claims[i], emailClaimPrefix) {
			authzClaims = append(authzClaims, claims[i])
		}
	}
	return authzClaims
}

// Create will create a user namespace.
func Create(ctx context.Context, manipulator manipulate.Manipulator, issuer string, claims []string) error {

	email, ok := getEmailFromClaims(claims)
	if !ok {
		return nil
	}

	namespaceName := namespaceUsers + "/" + email

	ns := api.NewNamespace()
	ns.Name = namespaceName
	ns.Namespace = namespaceUsers
	ns.Description = "Namespace for user " + email
	ns.CreateTime = time.Now()
	ns.UpdateTime = ns.CreateTime
	if err := ns.Validate(); err != nil {
		return err
	}

	mctx := manipulate.NewContext(ctx)
	err := manipulator.Create(mctx, ns)
	if err != nil {
		if !manipulate.IsConstraintViolationError(err) {
			return fmt.Errorf("unable to create user %s namespace: %w", email, err)
		}
		return nil
	}

	// Create authorization for the user in the /users/a@b.com ns
	authzClaims := getAuthzClaims(claims)
	auth := api.NewAuthorization()
	auth.Namespace = namespaceUsers
	auth.Name = email + "-user-authorization"
	auth.Description = "System generated authz policy for user " + email + " to access " + namespaceName
	auth.TrustedIssuers = []string{issuer}
	auth.Subject = [][]string{
		authzClaims,
	}
	auth.FlattenedSubject = auth.Subject[0]
	auth.Permissions = []string{"*:*"}
	auth.TargetNamespaces = []string{namespaceName}
	auth.Hidden = true
	auth.CreateTime = time.Now()
	auth.UpdateTime = auth.CreateTime
	mctx = manipulate.NewContext(ctx)
	return manipulator.Create(mctx, auth)
}
