package processors

import (
	"bytes"
	"context"
	"net/http"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authenticator"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

type NamespaceOwnerAuthorityFactory func(bahamut.Context) (func(context.Context) error, error)

// NewNamespaceOwnerAuthorizer binds the original namespace CRUD request and
// reuses current native crypto/revocation/resource/IP/restriction checks. The
// normal server auth chain remains mandatory; this is the async mutation fence.
func NewNamespaceOwnerAuthorizer(authn *authenticator.Authenticator, retriever permissions.Retriever) (NamespaceOwnerAuthorityFactory, error) {
	shared, err := NewNamespaceParticipationAuthorizer(authn, retriever)
	if err != nil {
		return nil, err
	}
	return func(original bahamut.Context) (func(context.Context) error, error) {
		if original == nil || original.Request() == nil {
			return nil, participationError(http.StatusForbidden)
		}
		r := original.Request()
		if r.Identity != api.NamespaceIdentity || (r.Operation != elemental.OperationCreate && r.Operation != elemental.OperationDelete) || ownerNamespaceRequest(original) != nil {
			return nil, participationError(http.StatusForbidden)
		}
		namespace, id, ip, bearer, operation := r.Namespace, r.ObjectID, r.ClientIP, token.FromRequest(r), r.Operation
		data := bytes.Clone(r.Data)
		bound := func() bool {
			current := original.Request()
			return current == r && current.Identity == api.NamespaceIdentity && current.Operation == operation && current.Namespace == namespace && current.ObjectID == id && current.ClientIP == ip && token.FromRequest(current) == bearer && bytes.Equal(current.Data, data) && ownerNamespaceRequest(original) == nil
		}
		check := func(ctx context.Context) error {
			return shared.checkNative(ctx, namespace, id, ip, bearer, api.NamespaceIdentity, operation, bound)
		}
		if err := check(original.Context()); err != nil {
			return nil, err
		}
		return check, nil
	}, nil
}

type authorizedNamespaceCreation struct {
	source namespacelifecycle.CreationSource
	check  func(context.Context) error
}

func (a authorizedNamespaceCreation) Verify(ctx context.Context, s namespacelifecycle.State) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	return a.source.Verify(ctx, s)
}
func (a authorizedNamespaceCreation) Insert(ctx context.Context, s namespacelifecycle.State) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	return a.source.Insert(ctx, s)
}
func (a authorizedNamespaceCreation) Observe(ctx context.Context, s namespacelifecycle.State) (string, error) {
	if err := a.check(ctx); err != nil {
		return "", err
	}
	return a.source.Observe(ctx, s)
}

type authorizedNamespaceDeletion struct {
	source namespacelifecycle.DeletionSource
	check  func(context.Context) error
}

func (a authorizedNamespaceDeletion) Verify(ctx context.Context, s namespacelifecycle.State) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	return a.source.Verify(ctx, s)
}
func (a authorizedNamespaceDeletion) HasChildren(ctx context.Context, n namespacelifecycle.Namespace) (bool, error) {
	if err := a.check(ctx); err != nil {
		return false, err
	}
	return a.source.HasChildren(ctx, n)
}
func (a authorizedNamespaceDeletion) Delete(ctx context.Context, s namespacelifecycle.State) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	return a.source.Delete(ctx, s)
}
