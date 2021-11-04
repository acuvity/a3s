package issuer

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"

	"go.aporeto.io/a3s/pkgs/token"
)

// MTLSIssuer issues IdentityToken from a TLS certificate.
type MTLSIssuer struct {
	subject            pkix.Name
	serialNumber       string
	emailAddresses     []string
	dnsNames           []string
	token              *token.IdentityToken
	caPool             *x509.CertPool
	signerFingerprints []string
}

// NewMTLSIssuer returns a new MTLSIssuer.
func NewMTLSIssuer(pool *x509.CertPool, sourceNamespace string, sourceName string) *MTLSIssuer {

	return &MTLSIssuer{
		token: token.NewIdentityToken(token.Source{
			Type:      "mtls",
			Namespace: sourceNamespace,
			Name:      sourceName,
		}),
		caPool: pool,
	}
}

// FromCertificate prepares the issuer according to the provided x509.Certificate.
func (c *MTLSIssuer) FromCertificate(certificate *x509.Certificate) error {

	chains, err := certificate.Verify(x509.VerifyOptions{
		Roots:     c.caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("unable Verify certificate: %w", err)
	}

	for _, chain := range chains {
		for _, cert := range chain {
			c.signerFingerprints = append(
				c.signerFingerprints,
				fmt.Sprintf("%02X", sha1.Sum(cert.Raw)),
			)
		}
	}

	c.subject = certificate.Subject
	c.serialNumber = certificate.SerialNumber.String()

	c.emailAddresses = make([]string, len(certificate.EmailAddresses))
	for i, addr := range certificate.EmailAddresses {
		c.emailAddresses[i] = addr
	}

	c.dnsNames = make([]string, len(certificate.DNSNames))
	for i, dns := range certificate.DNSNames {
		c.dnsNames[i] = dns
	}

	return nil
}

// Issue issues the token.IdentityToken derived from the the user certificate.
func (c *MTLSIssuer) Issue() *token.IdentityToken {

	if v := c.subject.CommonName; v != "" {
		c.token.Identity = append(c.token.Identity, fmt.Sprintf("commonname=%s", v))
	}

	if v := c.serialNumber; v != "" {
		c.token.Identity = append(c.token.Identity, fmt.Sprintf("serialnumber=%s", v))
	}

	if vs := c.subject.Country; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("country=%s", v))
		}
	}

	if vs := c.subject.Locality; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("locality=%s", v))
		}
	}

	if vs := c.subject.Organization; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("organization=%s", v))
		}
	}

	if vs := c.subject.OrganizationalUnit; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("organizationalunit=%s", v))
		}
	}

	if vs := c.subject.PostalCode; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("postalcode=%s", v))
		}
	}

	if vs := c.subject.Province; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("province=%s", v))
		}
	}

	if vs := c.subject.StreetAddress; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("streetaddress=%s", v))
		}
	}

	if vs := c.emailAddresses; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("email=%s", v))
		}
	}

	if vs := c.dnsNames; len(vs) != 0 {
		for _, v := range vs {
			c.token.Identity = append(c.token.Identity, fmt.Sprintf("dnsname=%s", v))
		}
	}

	if len(c.signerFingerprints) > 0 {
		// if > 0 it is guaranteed to have at least 2 items.
		c.token.Identity = append(c.token.Identity, fmt.Sprintf("fingerprint=%s", c.signerFingerprints[0]))
		c.token.Identity = append(c.token.Identity, fmt.Sprintf("issuerchain=%s", strings.Join(c.signerFingerprints[1:], ",")))
	}

	return c.token
}
