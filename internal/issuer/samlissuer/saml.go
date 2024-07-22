package samlissuer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	saml2 "github.com/russellhaering/gosaml2"
	"go.acuvity.ai/a3s/internal/identitymodifier"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
)

// New returns a new Azure issuer.
func New(ctx context.Context, source *api.SAMLSource, assertion *saml2.AssertionInfo) (token.Issuer, error) {

	c := newSAMLIssuer(source)
	if err := c.fromAssertion(ctx, assertion); err != nil {
		return nil, err
	}
	return c, nil
}

type samlIssuer struct {
	source *api.SAMLSource
	token  *token.IdentityToken
}

func newSAMLIssuer(source *api.SAMLSource) *samlIssuer {
	return &samlIssuer{
		source: source,
		token: token.NewIdentityToken(token.Source{
			Type:      "saml",
			Namespace: source.Namespace,
			Name:      source.Name,
		}),
	}
}

// Issue returns the IdentityToken.
func (c *samlIssuer) Issue() *token.IdentityToken {

	return c.token
}

func (c *samlIssuer) fromAssertion(ctx context.Context, assertion *saml2.AssertionInfo) (err error) {

	c.token.Identity = computeSAMLAssertion(assertion)

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

func computeSAMLAssertion(assertion *saml2.AssertionInfo) []string {

	out := []string{"nameid=" + assertion.NameID}

	for k, v := range assertion.Values {

		k = strings.TrimLeft(k, "@")

		for _, vv := range v.Values {

			if strings.Contains(vv.Value, "@") {
				fmt.Println(vv.Value)
				vv.Value = strings.ToLower(vv.Value)
			}

			out = append(out, fmt.Sprintf("%s=%s", k, vv.Value))
		}
	}

	sort.Strings(out)

	return out
}
