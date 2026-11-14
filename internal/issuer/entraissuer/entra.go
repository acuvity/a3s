package entraissuer

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.acuvity.ai/a3s/internal/identitymodifier"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/a3s/pkgs/token"
)

// New returns a new Entra issuer from an Entra v2 access token. The token
// must have been issued by the tenant of the source through cfg.LoginURL, for
// cfg.APIAppID, to one of cfg.NativeAppIDs, with cfg.Scope.
func New(
	ctx context.Context,
	source *api.EntraSource,
	tokenString string,
	cfg Config,
	requestMaker netsafe.RequestMaker,
) (token.Issuer, error) {

	tenantID := strings.ToLower(source.TenantID)
	keySet := oidc.NewRemoteKeySet(ctx, fmt.Sprintf("%s/%s/discovery/v2.0/keys", strings.TrimSuffix(cfg.LoginURL, "/"), tenantID))

	c := newEntraIssuer(source, requestMaker)
	if err := c.fromToken(ctx, tokenString, keySet, cfg); err != nil {
		return nil, err
	}

	return c, nil
}

type entraIssuer struct {
	token        *token.IdentityToken
	source       *api.EntraSource
	requestMaker netsafe.RequestMaker
}

func newEntraIssuer(source *api.EntraSource, requestMaker netsafe.RequestMaker) *entraIssuer {

	return &entraIssuer{
		source:       source,
		requestMaker: requestMaker,
		token: token.NewIdentityToken(token.Source{
			Type:      "entra",
			Namespace: source.Namespace,
			Name:      source.Name,
		}),
	}
}

// Issue returns the IdentityToken.
func (c *entraIssuer) Issue() *token.IdentityToken {

	return c.token
}

func (c *entraIssuer) fromToken(
	ctx context.Context,
	tokenString string,
	keySet oidc.KeySet,
	cfg Config,
) error {

	tenantID := strings.ToLower(c.source.TenantID)

	// The verifier checks the signature, the expiration, the audience and
	// the issuer, which locks the token to the tenant of the source.
	verifier := oidc.NewVerifier(
		fmt.Sprintf("%s/%s/v2.0", strings.TrimSuffix(cfg.LoginURL, "/"), tenantID),
		keySet,
		&oidc.Config{ClientID: cfg.APIAppID},
	)

	idt, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		return ErrEntra{Err: fmt.Errorf("unable to verify token: %w", err)}
	}

	claims := entraJWT{}
	if err := idt.Claims(&claims); err != nil {
		return ErrEntra{Err: fmt.Errorf("unable to decode token claims: %w", err)}
	}

	if err := validateClaims(claims, tenantID, cfg.NativeAppIDs, cfg.Scope); err != nil {
		return ErrEntra{Err: err}
	}

	c.token.Identity = computeEntraClaims(claims)

	if srcmod := c.source.Modifier; srcmod != nil {

		m, err := identitymodifier.NewRemote(srcmod, c.token.Source, c.requestMaker)
		if err != nil {
			return fmt.Errorf("unable to prepare source modifier: %w", err)
		}

		if c.token.Identity, err = m.Modify(ctx, c.token.Identity); err != nil {
			return fmt.Errorf("unable to call modifier: %w", err)
		}
	}

	return nil
}

func validateClaims(claims entraJWT, tenantID string, nativeAppIDs []string, scope string) error {

	if claims.Version != "2.0" {
		return fmt.Errorf("unsupported token version '%s'", claims.Version)
	}

	if claims.TID != tenantID {
		return fmt.Errorf("unexpected tenant '%s'", claims.TID)
	}

	if !slices.Contains(nativeAppIDs, claims.AZP) {
		return fmt.Errorf("unexpected authorized party '%s'", claims.AZP)
	}

	if !slices.Contains(strings.Fields(claims.SCP), scope) {
		return fmt.Errorf("missing scope '%s'", scope)
	}

	// Users in too many groups get a reference to Microsoft Graph instead of
	// the groups claim. Issuing without them would silently drop group based
	// authorizations.
	if _, ok := claims.ClaimNames["groups"]; ok {
		return fmt.Errorf("group overage is not supported")
	}

	return nil
}

// computeEntraClaims follows the claim keys of the Entra autologin of MTLS
// sources, without nameid, which only duplicates oid. The access token carries
// neither the group names nor the given name and surname, and name is only set
// from the UPN, which the tenant controls.
func computeEntraClaims(claims entraJWT) []string {

	out := []string{
		"tenantid=" + claims.TID,
		"oid=" + claims.OID,
	}

	if claims.UPN != "" {
		out = append(out, "name="+claims.UPN)
	}

	if claims.Name != "" {
		out = append(out, "displayname="+claims.Name)
	}

	if claims.Email != "" {
		out = append(out, "email="+claims.Email)
	}

	for _, g := range claims.Groups {
		out = append(out, "group:id="+g)
	}

	return out
}
