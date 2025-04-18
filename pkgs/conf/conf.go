package conf

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/tg/tglib"
)

// HTTPTimeoutsConf holds http server timeout.
type HTTPTimeoutsConf struct {
	TimeoutIdle  time.Duration `mapstructure:"timeout-idle" desc:"Idle timeout for the http requests" default:"240s"`
	TimeoutRead  time.Duration `mapstructure:"timeout-read" desc:"Read timeout for the http requests" default:"120s"`
	TimeoutWrite time.Duration `mapstructure:"timeout-write" desc:"Write timeout for the http requests" default:"240s"`
}

// LoggingConf is the configuration for log.
type LoggingConf struct {
	LogFormat    string `mapstructure:"log-format" desc:"Log format" default:"json"`
	LogLevel     string `mapstructure:"log-level" desc:"Log level" default:"info"`
	LogTracerURL string `mapstructure:"log-tracer" desc:"url of opentracing collector"`
}

// RateLimitingConf holds the configuration for rate limiting.
type RateLimitingConf struct {
	RateLimitingBurst   int  `mapstructure:"rate-limit-burst" desc:"Burst value" default:"500"`
	RateLimitingEnabled bool `mapstructure:"rate-limit-enabled" desc:"Enable global rate limiting"`
	RateLimitingRPS     int  `mapstructure:"rate-limit-rps" desc:"Requests per seconds" default:"2000"`
}

// ProfilingConf holds the configuration for profiling.
type ProfilingConf struct {
	ProfilingEnabled       bool   `mapstructure:"profiling-enabled" desc:"Enable the profiling server"`
	ProfilingListenAddress string `mapstructure:"profiling-listen" desc:"Listening address for the profiling server" default:":6060"`
}

// HealthConfiguration holds the configuration for health.
type HealthConfiguration struct {
	EnableHealth        bool   `mapstructure:"health-enabled" desc:"Enable the health check server"`
	HealthListenAddress string `mapstructure:"health-listen" desc:"Listening address for the health server" default:":80"`
}

// TLSConf can be used as a conf for a server that needs a tls.Config.
type TLSConf struct {
	TLSCertificate string   `mapstructure:"tls-cert" desc:"Path to the certificate for https"`
	TLSClientCAs   []string `mapstructure:"tls-client-ca" desc:"Path to the CA to use to verify client certificates"`
	TLSDisable     bool     `mapstructure:"tls-disable" desc:"Completely disable TLS support"`
	TLSKey         string   `mapstructure:"tls-key" desc:"Path to the key for https"`
	TLSKeyPass     string   `mapstructure:"tls-key-pass" desc:"Password for the key" secret:"true" file:"true"`

	certs     []*x509.Certificate
	clientCAs []*x509.Certificate
	tlsConfig *tls.Config
}

// Certificate returns the computed certificate.
func (c *TLSConf) Certificate() []*x509.Certificate {
	if c.certs == nil {
		_, _ = c.TLSConfig()
	}
	return c.certs
}

// ClientCertificateAuthority returns the computed Certificate authority to verify clients.
func (c *TLSConf) ClientCertificateAuthority() []*x509.Certificate {
	if c.clientCAs == nil {
		_, _ = c.TLSConfig()
	}
	return c.clientCAs
}

// TLSConfig returns the configured TLS configuration as *tls.Config.
func (c *TLSConf) TLSConfig() (*tls.Config, error) {

	if c.TLSDisable {
		return nil, nil
	}

	if c.tlsConfig != nil {
		return c.tlsConfig, nil
	}

	tlscfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if len(c.TLSClientCAs) > 0 {

		pool := x509.NewCertPool()

		for i, ca := range c.TLSClientCAs {
			caData, err := os.ReadFile(ca)
			if err != nil {
				return nil, fmt.Errorf("unable to load ca file %d: %w", i, err)
			}
			certs, err := tglib.ParseCertificates(caData)
			if err != nil {
				return nil, fmt.Errorf("unable to parse to ca certificate: %w", err)
			}
			c.clientCAs = append(c.clientCAs, certs...)
		}

		for _, cert := range c.clientCAs {
			pool.AddCert(cert)
		}

		tlscfg.ClientCAs = pool
	}

	if c.TLSCertificate != "" {
		certs, key, err := tglib.ReadCertificatePEMs(c.TLSCertificate, c.TLSKey, c.TLSKeyPass)
		if err != nil {
			return nil, fmt.Errorf("unable to load client certificate: %w", err)
		}
		c.certs = certs

		tlscert, err := tglib.ToTLSCertificates(certs, key)
		if err != nil {
			return nil, fmt.Errorf("unable to convert to tls.Certificate: %w", err)
		}
		tlscfg.Certificates = []tls.Certificate{tlscert}
	}

	c.tlsConfig = tlscfg

	return tlscfg, nil
}

// TLSAutoConf can be used as a conf for a service that receives a CA it can
// use to generate its own TLS certificates.
type TLSAutoConf struct {
	AutoTLSCA         string   `mapstructure:"auto-tls-ca" desc:"path to a CA used to automatically issue certificates"`
	AutoTLSCAKey      string   `mapstructure:"auto-tls-ca-key" desc:"path to the key of CA passed by auto-tls-ca"`
	AutoTLSCAKeyPass  string   `mapstructure:"auto-tls-ca-key-pass" desc:"passphrase for the key passed by auto-tls-ca-key" secret:"true" file:"true"`
	AutoTLSClientCAs  []string `mapstructure:"auto-tls-client-ca" desc:"Path to the CA to use to verify client certificates"`
	AutoTLSCommonName string   `mapstructure:"auto-tls-common-name" desc:"Set the pkix CommonName for the issued certificate"`
	AutoTLSDNSs       []string `mapstructure:"auto-tls-dns" desc:"Set the DNS SANs to use in the issued certificate. If set to 'auto' the hostname will be auto discovred" default:"auto"`
	AutoTLSDisable    bool     `mapstructure:"auto-tls-disable" desc:"Completely disable TLS support"`
	AutoTLSIPs        []string `mapstructure:"auto-tls-ip" desc:"Set the IP SANs to use in the issued certificate. If set to 'auto', the IP will be auto discovered" default:"auto"`

	caKey     crypto.PrivateKey
	caCert    *x509.Certificate
	certs     []*x509.Certificate
	clientCAs []*x509.Certificate
	dnss      []string
	ips       []string
	tlsConfig *tls.Config
}

// Certificate returns the current certificate issued.
func (c *TLSAutoConf) Certificate() []*x509.Certificate {
	if c.certs == nil {
		_, _ = c.TLSConfig()
	}
	return c.certs
}

// ClientCertificateAuthority returns the computed Client Certificate authority used to verfy clients.
func (c *TLSAutoConf) ClientCertificateAuthority() []*x509.Certificate {
	if c.clientCAs == nil {
		_, _ = c.TLSConfig()
	}
	return c.clientCAs
}

// Info returns IP and DNS SANs.
func (c *TLSAutoConf) Info() (ips []string, dns []string) {
	if c.certs == nil {
		_, _ = c.TLSConfig()
	}
	return c.ips, c.dnss
}

// TLSConfig returns a TLS config using the configured CA to create the needed certificates.
func (c *TLSAutoConf) TLSConfig() (*tls.Config, error) {

	if c.AutoTLSDisable {
		return nil, nil
	}

	if c.tlsConfig != nil {
		return c.tlsConfig, nil
	}

	tlscfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if len(c.AutoTLSClientCAs) > 0 {

		pool := x509.NewCertPool()

		for i, ca := range c.AutoTLSClientCAs {
			caData, err := os.ReadFile(ca)
			if err != nil {
				return nil, fmt.Errorf("unable to load ca file %d: %w", i, err)
			}
			certs, err := tglib.ParseCertificates(caData)
			if err != nil {
				return nil, fmt.Errorf("unable to parse to ca certificate: %w", err)
			}
			c.clientCAs = append(c.clientCAs, certs...)
		}

		for _, cert := range c.clientCAs {
			pool.AddCert(cert)
		}

		tlscfg.ClientCAs = pool
	}

	var err error
	if c.caCert == nil {
		c.caCert, c.caKey, err = tglib.ReadCertificatePEM(c.AutoTLSCA, c.AutoTLSCAKey, c.AutoTLSCAKeyPass)
		if err != nil {
			return nil, fmt.Errorf("unable to load ca certificate for auto tls: %w", err)
		}
	}

	var ips []string
	var autoIPs bool
	if len(c.AutoTLSIPs) == 1 && c.AutoTLSIPs[0] == "auto" {
		autoIPs = true
	}

	var dnss []string
	var autoDNSs bool
	if len(c.AutoTLSDNSs) == 1 && c.AutoTLSDNSs[0] == "auto" {
		autoDNSs = true
	}

	if autoDNSs || autoIPs {
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve hostname: %w", err)
		}

		if autoDNSs {
			dnss = []string{host, "localhost"}
		}

		if autoIPs {
			addrs, err := net.LookupHost(host)
			if err != nil {
				return nil, fmt.Errorf("unable to resolve hostname: %w", err)
			}

			if len(addrs) == 0 {
				return nil, fmt.Errorf("unable to find any IP in resolved hostname")
			}

			ips = append(addrs, "127.0.0.1")
		}
	}

	if len(dnss) == 0 {
		dnss = c.AutoTLSDNSs
	}

	if len(ips) == 0 {
		ips = c.AutoTLSIPs
	}

	netips := []net.IP{}
	for _, ip := range ips {
		if pip := net.ParseIP(ip); pip != nil {
			netips = append(netips, pip)
		}
	}

	c.dnss = dnss
	c.ips = ips

	opts := []tglib.IssueOption{
		tglib.OptIssueIPSANs(netips...),
		tglib.OptIssueDNSSANs(dnss...),
		tglib.OptIssueSigner(c.caCert, c.caKey),
		tglib.OptIssueTypeServerAuth(),
	}

	certPem, keyPem, err := tglib.Issue(pkix.Name{CommonName: c.AutoTLSCommonName}, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to issue auto tls certificate: %w", err)
	}

	key, err := tglib.PEMToKey(keyPem)
	if err != nil {
		return nil, fmt.Errorf("unable to convert key pem block to x509 key: %w", err)
	}

	certs, err := x509.ParseCertificates(certPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to convert cert pem block to x509 key: %w", err)
	}
	c.certs = certs

	tlsCert, err := tglib.ToTLSCertificates(certs, key)
	if err != nil {
		return nil, fmt.Errorf("unable to convert x509 cert and key to tls.Certificate: %w", err)
	}

	tlscfg.Certificates = append(tlscfg.Certificates, tlsCert)

	c.tlsConfig = tlscfg

	return tlscfg, nil
}

// APIServerConf holds the basic server conf.
type APIServerConf struct {
	CORSAdditionalOrigins []string `mapstructure:"cors-additional-origins" desc:"Set additional allowed origin for CORS"`
	CORSDefaultOrigin     string   `mapstructure:"cors-default-origin" desc:"Set the default allowed origin for CORS"`
	ListenAddress         string   `mapstructure:"listen" desc:"Listening address" default:":443"`
	MaxConnections        int      `mapstructure:"max-conns" desc:"Max number concurrent TCP connection"`
	MaxProcs              int      `mapstructure:"max-procs" desc:"Set the max number thread Go will start"`
	PublicAPIURL          string   `mapstructure:"public-api-url" desc:"Publicly announced API URL"`
	PrivateAPIURL         string   `mapstructure:"private-api-url" desc:"The private api url to use instead of the public api url" default:""`
}

// MongoConf holds the configuration for mongo db authentication.
type MongoConf struct {
	MongoAttrEncryptKey string `mapstructure:"mongo-encryption-key" desc:"Key to use for attributes encryption" secret:"true" file:"true"`
	MongoAuthDB         string `mapstructure:"mongo-auth-db" desc:"Database to use for authenticating" default:"admin"`
	MongoConsistency    string `mapstructure:"mongo-consistency" desc:"Set the read consistency" default:"nearest" allowed:"strong,monotonic,eventual,nearest,weakest"`
	MongoDBName         string `mapstructure:"mongo-db" desc:"Database name in MongoDB" default:"override-me"`
	MongoPassword       string `mapstructure:"mongo-pass" desc:"Password to use to connect to MongoDB" secret:"true" file:"true"`
	MongoPoolSize       int    `mapstructure:"mongo-pool-size" desc:"Maximum size of the connection pool" default:"4096"`
	MongoTLSCA          string `mapstructure:"mongo-tls-ca" desc:"Path to the CA used by MongoDB"`
	MongoTLSCertificate string `mapstructure:"mongo-tls-cert" desc:"Path to the client certificate"`
	MongoTLSDisable     bool   `mapstructure:"mongo-tls-disable" desc:"Set this to completely disable TLS" hidden:"true"`
	MongoTLSKey         string `mapstructure:"mongo-tls-key" desc:"Path to the client key"`
	MongoTLSKeyPass     string `mapstructure:"mongo-tls-key-pass" desc:"Password for the client key" secret:"true" file:"true"`
	MongoTLSSkip        bool   `mapstructure:"mongo-tls-skip" desc:"Skip CA verification"`
	MongoURL            string `mapstructure:"mongo-url" desc:"MongoDB connection string" required:"true"`
	MongoUser           string `mapstructure:"mongo-user" desc:"User to use to connect to MongoDB"`
}

// TLSConfig returns the configured TLS configuration as *tls.Config.
func (c *MongoConf) TLSConfig() (*tls.Config, error) {

	if c.MongoTLSDisable {
		return nil, nil
	}

	tlscfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if c.MongoTLSCA == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("unable to load system cert pool: %w", err)
		}
		tlscfg.RootCAs = pool
	} else {
		caData, err := os.ReadFile(c.MongoTLSCA)
		if err != nil {
			return nil, fmt.Errorf("unable to load ca file: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlscfg.RootCAs = pool
	}

	if c.MongoTLSCertificate != "" {
		cert, key, err := tglib.ReadCertificatePEM(c.MongoTLSCertificate, c.MongoTLSKey, c.MongoTLSKeyPass)
		if err != nil {
			return nil, fmt.Errorf("unable to load client certificate: %w", err)
		}
		tlscert, err := tglib.ToTLSCertificate(cert, key)
		if err != nil {
			return nil, fmt.Errorf("unable to convert to tls.Certificate: %w", err)
		}
		tlscfg.Certificates = []tls.Certificate{tlscert}
	}

	if c.MongoTLSSkip {
		tlscfg.InsecureSkipVerify = true
	}

	return tlscfg, nil
}

// NATSConf holds the configuration for pubsub connection.
type NATSConf struct {
	NATSClientID        string `mapstructure:"nats-client-id" desc:"Nats client ID"`
	NATSClusterID       string `mapstructure:"nats-cluster-id" desc:"Nats cluster ID" default:"test-cluster"`
	NATSCustomTLSConfig *tls.Config
	NATSPassword        string `mapstructure:"nats-pass" desc:"Password to use to connect to Nats" secret:"true" file:"true"`
	NATSTLSCA           string `mapstructure:"nats-tls-ca" desc:"Path to the CA used by Nats"`
	NATSTLSCertificate  string `mapstructure:"nats-tls-cert" desc:"Path to the client certificate"`
	NATSTLSDisable      bool   `mapstructure:"nats-tls-disable" desc:"Disable TLS completely"`
	NATSTLSKey          string `mapstructure:"nats-tls-key" desc:"Path to the client key"`
	NATSTLSKeyPass      string `mapstructure:"nats-tls-key-pass" desc:"Password for the client key" secret:"true" file:"true"`
	NATSTLSSkip         bool   `mapstructure:"nats-tls-skip" desc:"Skip CA verification"`
	NATSURL             string `mapstructure:"nats-url" desc:"URL of the nats service. If empty, start an in-memory nats server."`
	NATSUser            string `mapstructure:"nats-user" desc:"User name to use to connect to Nats" secret:"true" file:"true"`
}

// TLSConfig returns the configured TLS configuration as *tls.Config.
func (c *NATSConf) TLSConfig() (*tls.Config, error) {

	if c.NATSTLSDisable {
		return nil, nil
	}

	if c.NATSCustomTLSConfig != nil {
		return c.NATSCustomTLSConfig, nil
	}

	tlscfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if c.NATSTLSCA == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("unable to load system cert pool: %w", err)
		}
		tlscfg.RootCAs = pool
	} else {
		caData, err := os.ReadFile(c.NATSTLSCA)
		if err != nil {
			return nil, fmt.Errorf("unable to load ca file: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlscfg.RootCAs = pool
	}

	if c.NATSTLSCertificate != "" {
		cert, key, err := tglib.ReadCertificatePEM(c.NATSTLSCertificate, c.NATSTLSKey, c.NATSTLSKeyPass)
		if err != nil {
			return nil, fmt.Errorf("unable to load client certificate: %w", err)
		}
		tlscert, err := tglib.ToTLSCertificate(cert, key)
		if err != nil {
			return nil, fmt.Errorf("unable to convert to tls.Certificate: %w", err)
		}
		tlscfg.Certificates = []tls.Certificate{tlscert}
	}

	if c.NATSTLSSkip {
		tlscfg.InsecureSkipVerify = true
	}

	return tlscfg, nil
}

// NATSPublisherConf holds the config a Pubsub publisher.
type NATSPublisherConf struct {
	NATSPublishTopic string `mapstructure:"nats-publish-topic" desc:"Topic to use to push events" default:"events"`

	NATSConf `mapstructure:",squash"`
}

// NATSConsumerConf holds the config a Pubsub consumer.
type NATSConsumerConf struct {
	NATSGroupName      string `mapstructure:"nats-group-name" desc:"Nats group name" default:"main"`
	NATSSubscribeTopic string `mapstructure:"nats-subscribe-topic" desc:"Topic to use to receive updates" default:"override-me"`

	NATSConf `mapstructure:",squash"`
}

// MTLSHeaderConf holds the conf for the secure MTLS header.
type MTLSHeaderConf struct {
	Enabled                bool   `mapstructure:"mtls-header-enabled" desc:"Trust the value of the defined header containing a user certificate. This is insecure if there is no proper tls verification happening upstream"`
	HeaderForceHeaderKey   string `mapstructure:"mtls-header-force-header-key" desc:"If not empty, checking mtls will only be done from the header key if the request contains the given header" default:"X-Bahamut-Gateway"`
	HeaderForceHeaderValue string `mapstructure:"mtls-header-force-header-value" desc:"The value of the force header that will trigger a force mtls from headers" default:"public"`
	HeaderKey              string `mapstructure:"mtls-header-key" desc:"The header to check for user certificates" default:"x-tls-certificate"`
	Passphrase             string `mapstructure:"mtls-header-passphrase" desc:"The passphrase to decrypt the AES encrypted header content. It is mandatory if --mtls-header-enabled is set." secret:"true" file:"true"`
}

// A3SClientConf holds a3s config.
type A3SClientConf struct {
	A3SCertificateAuthority string `mapstructure:"a3s-cacert" desc:"Path to the CA certificate" secret:"true" file:"true"`
	A3SClientCert           string `mapstructure:"a3s-cert" desc:"Path to the client certificate" secret:"true" file:"true"`
	A3SClientKey            string `mapstructure:"a3s-key" desc:"Path to the client key" secret:"true" file:"true"`
	A3SClientKeyPass        string `mapstructure:"a3s-key-pass" desc:"Password for the client key" secret:"true" file:"true"`
	A3SNamespace            string `mapstructure:"a3s-namespace" desc:"Namespace"`
	A3SURL                  string `mapstructure:"a3s-url" desc:"URL of the a3s server" `
	A3SourceName            string `mapstructure:"a3s-source-name" desc:"Name of the source to utilize by default" default:"gateway"`

	systemCAPool *x509.CertPool
}

// SystemCAPool returns the system signing pool
func (c *A3SClientConf) SystemCAPool() (*x509.CertPool, error) {

	if c.A3SCertificateAuthority == "" {
		return nil, fmt.Errorf("no system certificate provided")
	}

	if c.systemCAPool != nil {
		return c.systemCAPool, nil
	}

	data, err := os.ReadFile(c.A3SCertificateAuthority)
	if err != nil {
		return nil, err
	}

	c.systemCAPool = x509.NewCertPool()
	if !c.systemCAPool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("unable to append system signing ca")
	}

	return c.systemCAPool, nil
}

// GatewayConf holds the configuration for the bahamut gateway behaviors.
type GatewayConf struct {
	GWAnnouncePrefix   string   `mapstructure:"gw-announce-prefix" desc:"Sets the prefix to use for the bahaamut gateway announcement"`
	GWAnnouncedAddress string   `mapstructure:"gw-announce-address" desc:"If set, announce as the service address to the gateway"`
	GWOverridePrivate  []string `mapstructure:"gw-override-private" desc:"Overrides the api public/private. In form <name>:<override>. namespace:private makes namespaces api private on the gateway"`
	GWAPIsHidden       []string `mapstructure:"gw-hidden-api" desc:"Set the list of api that will be completely hidden to the gateway."`
	GWTopic            string   `mapstructure:"gw-topic" desc:"Topic to use for gateway services discovery"`
}

// GWPrivateOverrides returns the private overrides in the needed format.
func (c *GatewayConf) GWPrivateOverrides() map[elemental.Identity]bool {

	out := map[elemental.Identity]bool{}

	for _, v := range c.GWOverridePrivate {
		parts := strings.SplitN(v, ":", 2)
		identity := api.Manager().IdentityFromAny(parts[0])
		if parts[0] == "*" {
			for _, i := range api.AllIdentities() {
				out[i] = parts[1] == "private"
			}
			continue
		}
		out[identity] = parts[1] == "private"
	}

	return out
}

// GWHiddenAPIs returns the list of hidden API in the needed format.
func (c *GatewayConf) GWHiddenAPIs() map[elemental.Identity]bool {

	out := map[elemental.Identity]bool{}

	for _, ident := range c.GWAPIsHidden {
		identity := api.Manager().IdentityFromAny(ident)
		out[identity] = true
	}

	return out
}
