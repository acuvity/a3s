package permissions

import (
	"context"
	"fmt"
	"net"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A Retriever is an object that can retrieve permissions
// for the given informations.
type Retriever interface {

	// Permissions returns the PermissionMap for the given
	// clams on the given namespace for the given id (optional)
	// from the given address with the given restrictions.
	Permissions(ctx context.Context, claims []string, ns string, opts ...RetrieverOption) (PermissionMap, error)

	// Revoked returns true if the given token ID is in a revocation list.
	Revoked(ctx context.Context, namespace string, tokenID string, claim []string) (bool, error)
}

type retriever struct {
	manipulator manipulate.Manipulator
}

// NewRetriever returns a new Retriever.
func NewRetriever(manipulator manipulate.Manipulator) Retriever {
	return &retriever{
		manipulator: manipulator,
	}
}

func (a *retriever) Permissions(ctx context.Context, claims []string, ns string, opts ...RetrieverOption) (PermissionMap, error) {

	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}

	// Handle token's authorizedNamespace.
	if cfg.restrictions.Namespace != "" {
		if cfg.restrictions.Namespace != ns && !elemental.IsNamespaceParentOfNamespace(cfg.restrictions.Namespace, ns) {
			return nil, nil
		}
	}

	if ns != "/" {
		count, err := a.countNamespace(ctx, ns)

		if err != nil {
			return nil, err
		}

		if count != 1 {
			return nil, nil // we don't return the error to the client or some namespace names may leak.
		}
	}

	groups, err := a.resolveGroupsMatchingClaims(ctx, claims, ns, cfg.label)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve groups: %w", err)
	}

	var groupClaims []string
	if len(groups) > 0 {

		if cfg.singleGroupMode {

			var group *api.Group
			maxWeight := -1
			for _, g := range groups {
				if g.Weight > maxWeight {
					maxWeight = g.Weight
					group = g
				}
			}
			groupClaims = []string{"@group:name=" + group.Name}

			if cfg.collectedGroups != nil {
				*cfg.collectedGroups = []string{group.Name}
			}

		} else {

			groupClaims = make([]string, len(groups))
			for i, g := range groups {
				groupClaims[i] = "@group:name=" + g.Name
			}

			if cfg.collectedGroups != nil {
				for _, g := range groups {
					*cfg.collectedGroups = append(*cfg.collectedGroups, g.Name)
				}
			}
		}
	}

	policies, err := a.resolvePoliciesMatchingClaims(ctx, append(claims, groupClaims...), ns, cfg.label)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve authorizations: %w", err)
	}

	out := PermissionMap{}
	accessibleNamespaces := map[string]struct{}{}

	for _, p := range policies {

		if len(p.Subject) == 0 || len(p.Subject[0]) == 0 {
			continue
		}

		var nsMatch bool
		for _, targetNS := range p.TargetNamespaces {
			if ns == targetNS || elemental.IsNamespaceChildrenOfNamespace(ns, targetNS) {
				nsMatch = true
				break
			}
		}

		if !nsMatch {
			continue
		}

		if l := len(p.Subnets); l > 0 {

			allowedSubnets := map[string]any{}
			for _, sub := range p.Subnets {
				allowedSubnets[sub] = struct{}{}
			}

			valid, err := validateClientIP(cfg.addr, allowedSubnets)
			if err != nil {
				return nil, err
			}
			if !valid {
				continue
			}
		}

		if cfg.accessibleNamespaces != nil {
			for _, n := range p.TargetNamespaces {
				accessibleNamespaces[n] = struct{}{}
			}
		}

		for identity, perms := range Parse(p.Permissions, cfg.id) {
			if _, ok := out[identity]; !ok {
				out[identity] = perms
			} else {
				for verb := range perms {
					if _, ok := out[identity][verb]; ok {
						out[identity][verb] = out[identity][verb] && perms[verb]
					} else {
						out[identity][verb] = perms[verb]
					}
				}
			}
		}
	}

	// If we have restrictions on permission from the token,
	// we reduce them.
	if !cfg.offloadPermissionsRestrictions && len(cfg.restrictions.Permissions) > 0 {
		out = out.Intersect(Parse(cfg.restrictions.Permissions, cfg.id))
	}

	// If we have restrictions on the origin networks from the token
	// we verify here.
	if len(cfg.restrictions.Networks) > 0 {
		allowedSubnets := map[string]any{}
		for _, net := range cfg.restrictions.Networks {
			allowedSubnets[net] = struct{}{}
		}
		valid, err := validateClientIP(cfg.addr, allowedSubnets)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, nil
		}
	}

	if cfg.accessibleNamespaces != nil {
		for k := range accessibleNamespaces {
			*cfg.accessibleNamespaces = append(*cfg.accessibleNamespaces, k)
		}
	}

	return out, nil
}

func (a *retriever) Revoked(ctx context.Context, namespace string, tokenID string, claims []string) (bool, error) {

	return checkRevocation(ctx, a.manipulator, namespace, tokenID, claims)
}

func (a *retriever) resolvePoliciesMatchingClaims(ctx context.Context, claims []string, ns string, label string) (api.AuthorizationsList, error) {

	mctx := manipulate.NewContext(
		ctx,
		manipulate.ContextOptionNamespace(ns),
		manipulate.ContextOptionPropagated(true),
		manipulate.ContextOptionFilter(
			makeAPIAuthorizationPolicyRetrieveFilter(claims, label),
		),
	)

	// Find all policies that are matching at least one claim
	policies := api.AuthorizationsList{}
	if err := a.manipulator.RetrieveMany(mctx, &policies); err != nil {
		return nil, err
	}

	// Ignore policies that are not matching all claims
	matchingPolicies := []*api.Authorization{}
	for _, p := range policies {
		if Match(p.Subject, claims) {
			matchingPolicies = append(matchingPolicies, p)
		}
	}

	return matchingPolicies, nil
}

func (a *retriever) resolveGroupsMatchingClaims(ctx context.Context, claims []string, ns string, label string) (api.GroupsList, error) {

	mctx := manipulate.NewContext(
		ctx,
		manipulate.ContextOptionNamespace(ns),
		manipulate.ContextOptionPropagated(true),
		manipulate.ContextOptionFilter(
			makeGroupsRetrieveFilter(claims, label),
		),
	)

	// Find all groups that are matching at least one claim
	groups := api.GroupsList{}
	if err := a.manipulator.RetrieveMany(mctx, &groups); err != nil {
		return nil, err
	}

	// Ignore groups that are not matching all claims
	matchingGroups := []*api.Group{}
	for _, p := range groups {
		if Match(p.Subject, claims) {
			matchingGroups = append(matchingGroups, p)
		}
	}

	return matchingGroups, nil
}

func validateClientIP(remoteAddr string, allowedSubnets map[string]any) (bool, error) {

	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ipStr = remoteAddr
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("missing or invalid origin IP '%s'", ipStr)
	}

	if ip.IsLoopback() {
		ip = net.IPv4(127, 0, 0, 1)
	} else {
		ip = ip.To4()
	}

	for sub := range allowedSubnets {

		_, subnet, err := net.ParseCIDR(sub)
		if err != nil {
			return false, err
		}

		if subnet.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

// makeAPIAuthorizationPolicyRetrieveFilter creates a manipulate filter to
// retrieve the api authorization policies matching the claims.
func makeAPIAuthorizationPolicyRetrieveFilter(claims []string, label string) *elemental.Filter {

	itags := []any{}
	set := mapset.NewSet()
	var issuer string
	for _, tag := range claims {
		if set.Add(tag) {
			itags = append(itags, tag)
			if strings.HasPrefix(tag, "@issuer=") {
				issuer = strings.TrimPrefix(tag, "@issuer=")
			}
		}
	}

	filter := elemental.NewFilterComposer().
		WithKey("flattenedsubject").In(itags...).
		WithKey("trustedissuers").Contains(issuer).
		WithKey("disabled").Equals(false).
		Done()

	if label != "" {
		filter = filter.WithKey("label").Equals(label).Done()
	}

	return filter
}

// makeGroupsRetrieveFilter creates a manipulate filter to
// retrieve the groups matching the claims.
func makeGroupsRetrieveFilter(claims []string, label string) *elemental.Filter {

	itags := []any{}
	set := mapset.NewSet()
	for _, tag := range claims {
		if set.Add(tag) {
			itags = append(itags, tag)
		}
	}

	filter := elemental.NewFilterComposer().
		WithKey("flattenedsubject").In(itags...).
		WithKey("disabled").Equals(false).
		Done()

	if label != "" {
		filter = filter.WithKey("label").Equals(label).Done()
	}

	return filter
}

// countNamespace tries to find the namespace in a two step process.
func (a *retriever) countNamespace(ctx context.Context, ns string) (int, error) {

	var count int
	var err error

	filter := elemental.NewFilterComposer().WithKey("name").Equals(ns).Done()

	if count, err = a.manipulator.Count(
		manipulate.NewContext(
			ctx,
			manipulate.ContextOptionFilter(filter),
			manipulate.ContextOptionRecursive(true),
		),
		api.NamespaceIdentity,
	); err != nil {
		return 0, err
	}

	if count == 0 {
		// If we could not find a namespace on the first attempt
		// try it a second time with strong read consistency,
		count, err = a.manipulator.Count(
			manipulate.NewContext(
				ctx,
				manipulate.ContextOptionReadConsistency(manipulate.ReadConsistencyStrong),
				manipulate.ContextOptionFilter(filter),
				manipulate.ContextOptionRecursive(true),
			),
			api.NamespaceIdentity,
		)
	}

	return count, err
}
