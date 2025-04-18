package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/permissions"
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

// ProcessCreate handles the creates requests for Permissionss.
func (p *PermissionsProcessor) ProcessCreate(bctx bahamut.Context) error {

	req := bctx.InputData().(*api.Permissions)

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
		bctx.Context(),
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

	bctx.SetOutputData(req)

	return nil
}

func permsToMap(p permissions.PermissionMap) map[string]map[string]bool {

	out := make(map[string]map[string]bool, len(p))

	for resource, perms := range p {
		out[resource] = make(map[string]bool, len(perms))
		for action, allowed := range perms {
			out[resource][action] = allowed
		}
	}

	return out
}
