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

	out := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	var clientCACert []*x509.Certificate

	if !autocfg.AutoTLSDisable {

		if autocfg.AutoTLSCA != "" {

			cfg, err := autocfg.TLSConfig()
			if err != nil {
				return nil, fmt.Errorf("unable to build server tls config from AutoTLS: %w", err)
			}

			ips, dnss := autocfg.Info()
			slog.Info("Auto TLS configured", "ips", ips, "dns", dnss)

			out.Certificates = append(out.Certificates, cfg.Certificates...)
		}

		if len(autocfg.AutoTLSClientCAs) > 0 {
			clientCACert = append(clientCACert, autocfg.ClientCertificateAuthority()...)
		}
	}

	if !manualcfg.TLSDisable {

		if manualcfg.TLSCertificate != "" {

			cfg, err := manualcfg.TLSConfig()
			if err != nil {
				return nil, fmt.Errorf("unable to build server tls config: %w", err)
			}
			out.Certificates = append(out.Certificates, cfg.Certificates...)
			slog.Info("Manual TLS configured")
		}

		if len(manualcfg.TLSClientCAs) > 0 {
			clientCACert = append(clientCACert, manualcfg.ClientCertificateAuthority()...)
		}
	}

	if len(clientCACert) > 0 {
		caPool := x509.NewCertPool()
		for _, ca := range clientCACert {
			caPool.AddCert(ca)
		}
		out.ClientCAs = caPool
	}

	return out, nil
}
