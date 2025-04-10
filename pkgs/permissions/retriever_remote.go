package permissions

import (
	"context"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/manipulate"
)

type remoteRetriever struct {
	manipulator manipulate.Manipulator
	transformer Transformer
}

// NewRemoteRetriever returns a new Retriever backed by remote API calls to
// an A3S instance, using the /permissions api.
// This is meant to be used with an authorizer.Authorizer by A3S client
// wishing to verify permissions for their users.
func NewRemoteRetriever(manipulator manipulate.Manipulator) Retriever {
	return &remoteRetriever{
		manipulator: manipulator,
	}
}

// NewRemoteRetrieverWithTransformer returns a new RemoteRetriever with the provided transformer.
func NewRemoteRetrieverWithTransformer(manipulator manipulate.Manipulator, transformer Transformer) Retriever {
	return &remoteRetriever{
		manipulator: manipulator,
		transformer: transformer,
	}
}

func (a *remoteRetriever) Permissions(ctx context.Context, claims []string, ns string, opts ...RetrieverOption) (PermissionMap, error) {

	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}

	preq := api.NewPermissions()
	preq.Claims = claims
	preq.Namespace = ns
	preq.ID = cfg.id
	preq.IP = cfg.addr
	preq.RestrictedNamespace = cfg.restrictions.Namespace
	preq.RestrictedNetworks = cfg.restrictions.Networks
	preq.RestrictedPermissions = cfg.restrictions.Permissions
	preq.OffloadPermissionsRestrictions = a.transformer != nil
	preq.CollectAccessibleNamespaces = cfg.accessibleNamespaces != nil
	preq.CollectGroups = cfg.collectedGroups != nil
	preq.SingleGroupMode = cfg.singleGroupMode

	if err := a.manipulator.Create(manipulate.NewContext(ctx), preq); err != nil {
		return nil, err
	}

	out := make(PermissionMap, len(preq.Permissions))
	for ident, perms := range preq.Permissions {
		out[ident] = perms
	}

	// Transform any roles into their identities and verbs
	if a.transformer != nil {
		out = a.transformer.Transform(out)
		if len(cfg.restrictions.Permissions) > 0 {
			out = out.Intersect(
				a.transformer.Transform(
					Parse(
						cfg.restrictions.Permissions,
						cfg.id,
					),
				),
			)
		}
	}

	if cfg.accessibleNamespaces != nil {
		*cfg.accessibleNamespaces = preq.CollectedAccessibleNamespaces
	}

	if cfg.collectedGroups != nil {
		*cfg.collectedGroups = preq.CollectedGroups
	}

	return out, nil
}

func (a *remoteRetriever) Revoked(ctx context.Context, namespace string, tokenID string, claims []string) (bool, error) {

	return checkRevocation(ctx, a.manipulator, namespace, tokenID, claims)
}
