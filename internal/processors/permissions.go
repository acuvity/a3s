package processors

import (
	"context"
	"fmt"
	"maps"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
)

// A PermissionsProcessor is a bahamut processor for Permissionss.
type PermissionsProcessor struct {
	retriever permissions.Retriever
}

// NewPermissionsProcessor returns a new PermissionsProcessor.
func NewPermissionsProcessor(retriever permissions.Retriever) *PermissionsProcessor {
	return &PermissionsProcessor{
		retriever: retriever,
	}
}

func (p *PermissionsProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {

	idt, err := token.ParseUnverified(bctx.Request().Password)
	if err != nil {
		return fmt.Errorf("unable to reparse idt token: %w", err)
	}

	req := api.NewPermissions()
	req.Namespace = bctx.Request().Namespace
	req.Claims = bctx.Claims()

	if idt.Restrictions != nil {
		req.RestrictedNamespace = idt.Restrictions.Namespace
		req.RestrictedNetworks = idt.Restrictions.Networks
		req.RestrictedPermissions = idt.Restrictions.Permissions
	}

	bctx.SetOutputData(api.PermissionsList{p.check(bctx.Context(), req)})

	return nil
}

// ProcessCreate handles the creates requests for Permissionss.
func (p *PermissionsProcessor) ProcessCreate(bctx bahamut.Context) error {

	req := bctx.InputData().(*api.Permissions)

	bctx.SetOutputData(p.check(bctx.Context(), req))

	return nil
}

func (p *PermissionsProcessor) check(ctx context.Context, req *api.Permissions) *api.Permissions {

	restrictions := permissions.Restrictions{
		Namespace:   req.RestrictedNamespace,
		Networks:    req.RestrictedNetworks,
		Permissions: req.RestrictedPermissions,
	}

	var collectedNamespaces []string
	if req.CollectAccessibleNamespaces {
		collectedNamespaces = []string{}
	}

	var collectedGroups []string
	if req.CollectGroups {
		collectedGroups = []string{}
	}

	perms, err := p.retriever.Permissions(
		ctx,
		req.Claims,
		req.Namespace,
		permissions.OptionRetrieverID(req.ID),
		permissions.OptionRetrieverSourceIP(req.IP),
		permissions.OptionRetrieverRestrictions(restrictions),
		permissions.OptionOffloadPermissionsRestrictions(req.OffloadPermissionsRestrictions),
		permissions.OptionSingleGroupMode(req.SingleGroupMode),
		permissions.OptionCollectAccessibleNamespaces(&collectedNamespaces),
		permissions.OptionCollectGroups(&collectedGroups),
	)

	switch err {
	case nil:
		req.Permissions = permsToMap(perms)
	default:
		req.Error = err.Error()
	}

	if len(collectedNamespaces) > 0 {
		req.CollectedAccessibleNamespaces = collectedNamespaces
	}

	if len(collectedGroups) > 0 {
		req.CollectedGroups = collectedGroups
	}

	return req
}

func permsToMap(p permissions.PermissionMap) map[string]map[string]bool {

	out := make(map[string]map[string]bool, len(p))

	for resource, perms := range p {
		out[resource] = make(map[string]bool, len(perms))
		maps.Copy(out[resource], perms)
	}

	return out
}
