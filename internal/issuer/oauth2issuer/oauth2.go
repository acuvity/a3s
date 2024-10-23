package oauth2issuer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"go.acuvity.ai/a3s/internal/identitymodifier"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
)

// New returns a new Azure issuer.
func New(ctx context.Context, source *api.OAuth2Source, claims map[string]any) (token.Issuer, error) {

	c := newOAuth2Issuer(source)
	if err := c.fromClaims(ctx, claims); err != nil {
		return nil, err
	}
	return c, nil
}

type oauth2Issuer struct {
	source *api.OAuth2Source
	token  *token.IdentityToken
}

func newOAuth2Issuer(source *api.OAuth2Source) *oauth2Issuer {
	return &oauth2Issuer{
		source: source,
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

func (c *oauth2Issuer) fromClaims(ctx context.Context, claims map[string]any) (err error) {

	c.token.Identity = computeOAuth2Claims(claims)

	if srcmod := c.source.Modifier; srcmod != nil {

		m, err := identitymodifier.NewRemote(srcmod, c.token.Source)
		if err != nil {
			return fmt.Errorf("unable to prepare source modifier: %w", err)
		}

		if c.token.Identity, err = m.Modify(ctx, c.token.Identity); err != nil {
			return fmt.Errorf("unable to call modifier: %w", err)
		}
	}

	return nil
}

func computeOAuth2Claims(claims map[string]any) []string {

	out := []string{}

	for k, v := range claims {
		k = strings.TrimLeft(k, "@")
		switch claim := v.(type) {
		case string:
			if k != "" {
				out = append(out, fmt.Sprintf("%s=%s", k, claim))
			}
		case []string:
			for _, item := range claim {
				if item != "" {
					out = append(out, fmt.Sprintf("%s=%s", k, item))
				}
			}
		case int:
			out = append(out, fmt.Sprintf("%s=%d", k, claim))

		case []int:
			for _, item := range claim {
				out = append(out, fmt.Sprintf("%s=%d", k, item))
			}
		case float64:
			out = append(out, fmt.Sprintf("%s=%f", k, claim))

		case []float64:
			for _, item := range claim {
				out = append(out, fmt.Sprintf("%s=%f", k, item))
			}

		case bool:
			out = append(out, fmt.Sprintf("%s=%t", k, claim))

		case []any:
			for _, item := range claim {
				if claimValue, ok := item.(string); ok {
					if claimValue != "" {
						out = append(out, fmt.Sprintf("%s=%s", strings.TrimLeft(k, "@"), claimValue))
					}
				}
			}
		case nil:
		default:
			out = append(out, fmt.Sprintf("%s=%s", k, v))
		}
	}

	sort.Strings(out)

	return out
}
