package oauth2issuer

import (
	"context"
	"fmt"
	"sort"

	"go.acuvity.ai/a3s/internal/identitymodifier"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/a3s/pkgs/token"
)

// New returns a new Azure issuer.
func New(ctx context.Context, source *api.OAuth2Source, claims []string, requestMaker netsafe.RequestMaker) (token.Issuer, error) {

	c := newOAuth2Issuer(source, requestMaker)
	if err := c.fromClaims(ctx, claims); err != nil {
		return nil, err
	}
	return c, nil
}

type oauth2Issuer struct {
	source       *api.OAuth2Source
	token        *token.IdentityToken
	requestMaker netsafe.RequestMaker
}

func newOAuth2Issuer(source *api.OAuth2Source, requestMaker netsafe.RequestMaker) *oauth2Issuer {
	return &oauth2Issuer{
		source:       source,
		requestMaker: requestMaker,
		token: token.NewIdentityToken(token.Source{
			Type:      "oauth2",
			Namespace: source.Namespace,
			Name:      source.Name,
		}),
	}
}

// Issue returns the IdentityToken.
func (c *oauth2Issuer) Issue() *token.IdentityToken {

	return c.token
}

func (c *oauth2Issuer) fromClaims(ctx context.Context, claims []string) (err error) {

	sort.Strings(claims)
	c.token.Identity = claims

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
