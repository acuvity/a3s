package authorizer

import (
	"context"
	"fmt"

	"go.aporeto.io/a3s/pkgs/api"
	"go.aporeto.io/manipulate"
)

// A UserNamespaceCreator is an interface that can create user namespaces.
type UserNamespaceCreator interface {
	Creator(ctx context.Context, claims []string) error
}

// creator is an object that implements
type creator struct {
	manipulator manipulate.Manipulator
}

// NewCreator returns a new UserNamespaceCreator.
func NewCreator(manipulator manipulate.Manipulator) UserNamespaceCreator {
	return &creator{
		manipulator: manipulator,
	}
}

func getEmailClaim(claims []string) *string {
	return nil
}

func (c *creator) Creator(ctx context.Context, claims []string) error {

	email := getEmailClaim(claims)
	if email == nil {
		return nil
	}

	ns := api.NewNamespace()
	ns.Name = *email

	mctx := manipulate.NewContext(ctx, manipulate.ContextOptionNamespace("/users"))
	if err := c.manipulator.Create(mctx, ns); err != nil {
		return fmt.Errorf("unable to create user %s namespace: %w", *email, err)
	}
	return nil
}
