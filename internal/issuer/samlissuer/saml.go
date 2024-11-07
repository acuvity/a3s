package samlissuer

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/karlseguin/ccache/v3"
	saml2 "github.com/russellhaering/gosaml2"
	types "github.com/russellhaering/gosaml2/types"
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

// InjectRemoteIDPMetadata retrieves the remove IDP metadata, then
// populates the IDPMetadata with them and calls InjectIDPMetadata.
// If IDPMetadataURL is empty, this function is a noop.
func InjectRemoteIDPMetadata(source *api.SAMLSource, cache *ccache.Cache[string]) error {

	if source.IDPMetadataURL == "" {
		return nil
	}

	if item := cache.Get(source.IDPMetadataURL); item != nil && !item.Expired() {

		source.IDPMetadata = item.Value()

	} else {

		resp, err := http.Get(source.IDPMetadataURL)
		if err != nil {
			return fmt.Errorf("unable to retrieve IDP Metadata from SAML source '%s' in namespace '%s': %w", source.Name, source.Namespace, err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("IDP Metdata server returned an error from SAML source '%s' in namespace '%s': %s", source.Name, source.Namespace, resp.Status)
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("unable to read IDP Metadata body: %w", err)
		}

		source.IDPMetadata = string(data)
		cache.Set(source.IDPMetadataURL, source.IDPMetadata, 1*time.Hour)
	}

	return InjectIDPMetadata(source)
}

// InjectIDPMetadata injects the data from the source's IDPMetadata in the
// relevant fields. If source.IDPMetadata is empty, this function is a noop.
func InjectIDPMetadata(source *api.SAMLSource) error {

	if source.IDPMetadata == "" {
		return nil
	}

	data := []byte(source.IDPMetadata)

	descriptor := &types.EntityDescriptor{}
	if err := xml.Unmarshal(data, descriptor); err != nil {
		return fmt.Errorf("unable to read xml content %s: %w", source.IDPMetadata, err)
	}

	if descriptor.IDPSSODescriptor != nil && len(descriptor.IDPSSODescriptor.SingleSignOnServices) > 0 {

		source.IDPURL = descriptor.IDPSSODescriptor.SingleSignOnServices[0].Location
		source.IDPIssuer = descriptor.EntityID

		certs := []string{}
		for _, kd := range descriptor.IDPSSODescriptor.KeyDescriptors {

			for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
				if xcert.Data == "" {
					return fmt.Errorf("metadata certificate at index %d must not be empty", idx)
				}

				certData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(xcert.Data))
				if err != nil {
					return fmt.Errorf("undable to decode metadata certificate at index %d: %w", idx, err)
				}

				certs = append(certs, string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certData,
				})))

			}
		}

		source.IDPCertificate = strings.Join(certs, "\n")
	} else if descriptor.SPSSODescriptor != nil && len(descriptor.SPSSODescriptor.AssertionConsumerServices) > 0 {
		source.IDPURL = descriptor.SPSSODescriptor.AssertionConsumerServices[0].Location
		source.IDPIssuer = descriptor.EntityID
	}

	source.IDPMetadata = ""

	return nil
}
