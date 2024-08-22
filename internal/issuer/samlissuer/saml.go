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

	inc, exc := computeSAMLInclusion(c.source)

	c.token.Identity = computeSAMLAssertion(assertion, inc, exc)

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

func computeSAMLAssertion(assertion *saml2.AssertionInfo, inc map[string]struct{}, exc map[string]struct{}) []string {

	out := []string{"nameid=" + assertion.NameID}

	for k, v := range assertion.Values {

		k = strings.TrimLeft(k, "@")

		if _, ok := exc[strings.ToLower(k)]; ok {
			continue
		}

		if len(inc) > 0 {
			if _, ok := inc[strings.ToLower(k)]; !ok {
				continue
			}
		}

		for _, vv := range v.Values {
			out = append(out, fmt.Sprintf("%s=%s", k, vv.Value))
		}
	}

	sort.Strings(out)

	return out
}

func computeSAMLInclusion(src *api.SAMLSource) (inc map[string]struct{}, exc map[string]struct{}) {

	inc = make(map[string]struct{}, len(src.IncludedKeys))
	for _, key := range src.IncludedKeys {
		inc[strings.ToLower(key)] = struct{}{}
	}

	exc = make(map[string]struct{}, len(src.IgnoredKeys))
	for _, key := range src.IgnoredKeys {
		exc[strings.ToLower(key)] = struct{}{}
	}

	return inc, exc
}
