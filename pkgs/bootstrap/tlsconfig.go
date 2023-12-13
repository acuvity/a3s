package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"

	"go.acuvity.ai/a3s/pkgs/conf"
)

// TLSConfig returns a *tls.Config given an TLSAutoConf and and manual TLSConfig
func TLSConfig(autocfg conf.TLSAutoConf, manualcfg conf.TLSConf) (*tls.Config, error) {

	var serverTLSConfig *tls.Config
	var err error

	clientCACert := []*x509.Certificate{}

	if autocfg.AutoTLSCA != "" && !autocfg.AutoTLSDisable {
		serverTLSConfig, err = autocfg.TLSConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to build server tls config from AutoTLS: %w", err)
		}
		clientCACert = append(clientCACert, autocfg.ClientCertificateAuthority()...)
		ips, dnss := autocfg.Info()
		slog.Info("Auto TLS configured",
			"ips", ips,
			"dns", dnss,
		)
	}

	if manualcfg.TLSCertificate != "" && !manualcfg.TLSDisable {
		manualServerTLSConfig, err := manualcfg.TLSConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to build server tls config: %w", err)
		}

		clientCACert = append(clientCACert, manualcfg.ClientCertificateAuthority()...)

		if serverTLSConfig == nil {
			serverTLSConfig = manualServerTLSConfig
		} else {
			serverTLSConfig.Certificates = append(serverTLSConfig.Certificates, manualServerTLSConfig.Certificates...)
			caPool := x509.NewCertPool()
			for _, ca := range clientCACert {
				caPool.AddCert(ca)
			}
			serverTLSConfig.ClientCAs = caPool
		}
		slog.Info("Manual TLS configured")
	}

	return serverTLSConfig, nil

}
