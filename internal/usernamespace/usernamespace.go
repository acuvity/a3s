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
	namespaceUsers   = "/users"
	emailClaimPrefix = "email="
)

func getEmailClaim(claims []string) (string, bool) {
	for i := 0; i < len(claims); i++ {
		if strings.HasPrefix(claims[i], emailClaimPrefix) {
			email := strings.TrimPrefix(claims[i], emailClaimPrefix)
			return email, true
		}
	}
	return "", false
}

// Create will create a user namespace.
func Create(ctx context.Context, manipulator manipulate.Manipulator, claims []string) error {

	email, ok := getEmailClaim(claims)
	if !ok {
		return nil
	}

	ns := api.NewNamespace()
	ns.Name = namespaceUsers + "/" + email
	ns.Namespace = namespaceUsers
	ns.Description = "Namespace for user " + email
	ns.CreateTime = time.Now()
	ns.UpdateTime = ns.CreateTime
	if err := ns.Validate(); err != nil {
		return err
	}

	mctx := manipulate.NewContext(ctx)
	if err := manipulator.Create(mctx, ns); err != nil && !manipulate.IsConstraintViolationError(err) {
		return fmt.Errorf("unable to create user %s namespace: %w", email, err)
	}

	return nil
}
