package main

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.acuvity.ai/a3s/pkgs/authenticator"
	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/a3s/pkgs/lombric"
	"go.acuvity.ai/a3s/pkgs/version"
	"go.acuvity.ai/tg/tglib"
)

// Conf holds the main configuration flags.
type Conf struct {
	AuditedIdentities         []string `mapstructure:"audited-identities" desc:"Identities that will be tracked for audit purposes" default:"issue"`
	BinaryModifier            string   `mapstructure:"binary-modifier" desc:"Path to modifier binary. If set, binary-modifier-sha256 must be set"`
	BinaryModifierHash        string   `mapstructure:"binary-modifier-sha256" desc:"Sha256 hash of the binary-modifier"`
	EntraNotifEndpoint        string   `mapstructure:"entra-notification-endpoint" desc:"The hook URL to use when subscribing to MS Graph notifications" default:"/idp/entra/events"`
	Init                      bool     `mapstructure:"init" desc:"If set, initialize the root permissions using the CAs passed in --init-root-ca and --init-platform-ca"`
	InitContinue              bool     `mapstructure:"init-continue" desc:"Continues normal boot after init."`
	InitDB                    bool     `mapstructure:"init-db" desc:"If set, initialize the database using the mongo config passed in and init-db-username"`
	InitDBUsername            string   `mapstructure:"init-db-username" desc:"If init-db is set, this will define the username to use on db initialization" default:"CN=a3s,OU=root,O=system"`
	InitData                  string   `mapstructure:"init-data" desc:"Path to an import file containing initial provisionning data"`
	InitPlatformCAPath        string   `mapstructure:"init-platform-ca" desc:"Path to the platform CA to use to initialize platform permissions"`
	InitRootUserCAPath        string   `mapstructure:"init-root-ca" desc:"Path to the root CA to use to initialize root permissions"`
	OIDSourceName             string   `mapstructure:"oid-source-name" desc:"For MTLS sources. OID to look for in the client certificate's DN to infer source name"`
	OIDSourceNamespace        string   `mapstructure:"oid-source-namespace" desc:"For MTLS sources. OID to look for in the client certificate's DN to infer source namespace"`
	PluginModifier            string   `mapstructure:"plugin-modifier" desc:"Path to a go plugin implemeting the plugin.Modifier interface"`
	RestrictedIgnoredNetworks []string `mapstructure:"restricted-cidr-ignore" desc:"list of CIDR that must be allowed, even if restricted by --restricted-cidr"`
	RestrictedNetworks        []string `mapstructure:"restricted-cidr" desc:"list of restricted CIDR. A3S will refuse to make calls to url provider by users to any host in that network. If empty, defaults to IANA private subnets definition"`

	JWT JWTConf `mapstructure:",squash"`

	conf.APIServerConf       `mapstructure:",squash"`
	conf.GatewayConf         `mapstructure:",squash"`
	conf.HTTPTimeoutsConf    `mapstructure:",squash"`
	conf.HealthConfiguration `mapstructure:",squash"`
	conf.LoggingConf         `mapstructure:",squash"`
	conf.MTLSHeaderConf      `mapstructure:",squash"`
	conf.MongoConf           `mapstructure:",squash" override:"mongo-db=a3s"`
	conf.NATSPublisherConf   `mapstructure:",squash"`
	conf.ProfilingConf       `mapstructure:",squash"`
	conf.RateLimitingConf    `mapstructure:",squash"`
	conf.RedisConf           `mapstructure:",squash"`
	conf.TLSAutoConf         `mapstructure:",squash"`
	conf.TLSConf             `mapstructure:",squash"`
}

// Prefix returns the configuration prefix.
func (c *Conf) Prefix() string { return "a3s" }

// PrintVersion prints the current version.
func (c *Conf) PrintVersion() {
	fmt.Println(version.String(c.Prefix()))
}

// SourceOIDs returns the parsed source name and namespace OIDs.
func (c *Conf) SourceOIDs() (name asn1.ObjectIdentifier, namespace asn1.ObjectIdentifier, err error) {

	parse := func(oid string) (asn1.ObjectIdentifier, error) {
		parts := strings.Split(oid, ".")
		o := asn1.ObjectIdentifier{}
		for _, digit := range parts {
			d, err := strconv.Atoi(digit)
			if err != nil {
				return nil, fmt.Errorf("unable to parse oid %s: %w", oid, err)
			}
			o = append(o, d)
		}
		return o, nil
	}

	if c.OIDSourceName != "" {
		if name, err = parse(c.OIDSourceName); err != nil {
			return nil, nil, fmt.Errorf("invalid --oid-source-name: %w", err)
		}
	}

	if c.OIDSourceNamespace != "" {
		if namespace, err = parse(c.OIDSourceNamespace); err != nil {
			return nil, nil, fmt.Errorf("invalid --oid-source-namespace: %w", err)
		}
	}

	return name, namespace, nil
}

func newConf() Conf {
	c := Conf{}
	lombric.Initialize(&c)
	return c
}

// JWTConf holds the configuration related to jwt management.
type JWTConf struct {
	JWTAudience            string        `mapstructure:"jwt-audience" desc:"Default audience for delivered jwt"`
	JWTCertPath            string        `mapstructure:"jwt-cert" desc:"Path to the certificate pem file use to sign the JWTs"`
	JWTCookieDomain        string        `mapstructure:"jwt-cookie-domain" desc:"Defines the domain for the cookie"`
	JWTCookiePolicy        string        `mapstructure:"jwt-cookie-policy" desc:"Define same site policy applied to token cookies" default:"strict" allowed:"strict,lax,none"`
	JWTDefaultValidity     time.Duration `mapstructure:"jwt-default-validity" desc:"Default duration of the validity of the issued tokens" default:"24h"`
	JWTForbiddenOpaqueKeys []string      `mapstructure:"jwt-forbidden-opaque-keys" desc:"List of forbidden opaque keys when issuing tokens"`
	JWTIssuer              string        `mapstructure:"jwt-issuer" desc:"Value used for issuer jwt field"`
	JWTKeyPass             string        `mapstructure:"jwt-key-pass" desc:"JWT certificate key password" secret:"true" file:"true"`
	JWTKeyPath             string        `mapstructure:"jwt-key" desc:"Path to the certificate key pem file used to sign to JWTs"`
	JWTMaxValidity         time.Duration `mapstructure:"jwt-max-validity" desc:"Maximum duration of the validity of the issued tokens" default:"720h"`
	JWTPreviousCertPaths   []string      `mapstructure:"jwt-previous-cert" desc:"Previous valid certificates to add the JWKS to allow rotation"`
	JWTTrustedIssuers      []string      `mapstructure:"jwt-trusted-issuer" desc:"List of externally trusted issuers"`
	JWTWaiveValiditySecret string        `mapstructure:"jwt-waive-validity-secret" desc:"The secret to use to waive max validity enforcement" file:"true" secret:"true"`

	jwtKey           crypto.PrivateKey
	jwtCert          *x509.Certificate
	previousJWTCerts []*x509.Certificate
}

// JWTCertificate returns the certificate used to verify JWTs.
func (c *JWTConf) JWTCertificate() (*x509.Certificate, crypto.PrivateKey, error) {

	if c.jwtCert != nil {
		return c.jwtCert, c.jwtKey, nil
	}

	jwtCert, jwtKey, err := tglib.ReadCertificatePEM(c.JWTCertPath, c.JWTKeyPath, c.JWTKeyPass)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read jwt certificate: %w", err)
	}

	c.jwtCert = jwtCert
	c.jwtKey = jwtKey

	return jwtCert, jwtKey, nil
}

// JWTPreviousCertificates returns the previous certificate used to verify JWTs.
func (c *JWTConf) JWTPreviousCertificates() ([]*x509.Certificate, error) {

	if c.previousJWTCerts != nil {
		return c.previousJWTCerts, nil
	}

	for _, path := range c.JWTPreviousCertPaths {
		jwtCert, err := tglib.ParseCertificatePEMs(path)
		if err != nil {
			return nil, fmt.Errorf("unable to read previous jwt certificate at '%s': %w", path, err)
		}
		c.previousJWTCerts = append(c.previousJWTCerts, jwtCert...)
	}

	return c.previousJWTCerts, nil
}

// TrustedIssuers parses --jwt-trusted-issuers and returns a list
// of prepopulated authenticator.RemoteIssuer.
func (c *JWTConf) TrustedIssuers() ([]authenticator.RemoteIssuer, error) {

	if len(c.JWTTrustedIssuers) == 0 {
		return nil, nil
	}

	out := make([]authenticator.RemoteIssuer, len(c.JWTTrustedIssuers))

	for i, r := range c.JWTTrustedIssuers {

		ri := authenticator.RemoteIssuer{}
		parts := strings.SplitN(r, "@", 2)

		ri.URL = parts[0]

		if len(parts) == 2 {
			cert, err := tglib.ParseCertificatePEM(parts[1])
			if err != nil {
				return nil, fmt.Errorf("unable to parse cert at '%s': %w", parts[1], err)
			}

			ri.Pool = x509.NewCertPool()
			ri.Pool.AddCert(cert)
		}

		out[i] = ri
	}

	return out, nil
}
