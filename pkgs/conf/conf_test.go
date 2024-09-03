package conf

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"reflect"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/tg/tglib"
)

func TestTLSConf(t *testing.T) {

	_, clientpool, tlscert := makeFixtures()

	Convey("disabled tls config", t, func() {
		cfg := TLSConf{
			TLSDisable: true,
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldBeNil)
	})

	Convey("tls config with client CA", t, func() {
		cfg := TLSConf{
			TLSClientCAs: []string{"fixtures/ca-cert.pem"},
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.ClientCAs.Equal(clientpool), ShouldBeTrue)
	})

	Convey("tls config with certificate", t, func() {
		cfg := TLSConf{
			TLSCertificate: "fixtures/cert-cert.pem",
			TLSKey:         "fixtures/cert-key.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.Certificates[0].Certificate, ShouldResemble, tlscert.Certificate)
	})

	Convey("tls config with bad certificate", t, func() {
		cfg := TLSConf{
			TLSCertificate: "fixtures/cert-key.pem",
			TLSKey:         "fixtures/cert-key.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load client certificate:")
	})

	Convey("tls config with bad ca", t, func() {
		cfg := TLSConf{
			TLSClientCAs: []string{"nope"},
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load ca file 0:")
	})
}

func TestAutoTLSConf(t *testing.T) {

	Convey("disabled tls config", t, func() {
		cfg := TLSAutoConf{
			AutoTLSDisable: true,
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldBeNil)
	})

	Convey("tls config with CA without auto discovery ", t, func() {
		cfg := TLSAutoConf{
			AutoTLSCA:        "fixtures/ca-cert.pem",
			AutoTLSCAKey:     "fixtures/ca-key.pem",
			AutoTLSIPs:       []string{"1.1.1.1", "2.2.2.2"},
			AutoTLSDNSs:      []string{"toto.com"},
			AutoTLSClientCAs: []string{"fixtures/cert-cert.pem"},
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)

		ips, dnss := cfg.Info()
		So(ips, ShouldResemble, []string{"1.1.1.1", "2.2.2.2"})
		So(dnss, ShouldResemble, []string{"toto.com"})
	})

	Convey("tls config with CA with auto discovery ", t, func() {
		cfg := TLSAutoConf{
			AutoTLSCA:    "fixtures/ca-cert.pem",
			AutoTLSCAKey: "fixtures/ca-key.pem",
			AutoTLSIPs:   []string{"auto"},
			AutoTLSDNSs:  []string{"auto"},
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)

		ips, dnss := cfg.Info()
		So(ips, ShouldNotContain, "auto")
		So(dnss, ShouldNotContain, "auto")
	})

	Convey("tls config with bad ca", t, func() {
		cfg := TLSAutoConf{
			AutoTLSCA:    "fixtures/ca-key.pem",
			AutoTLSCAKey: "fixtures/ca-key.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load ca certificate for auto tls:")
	})

	Convey("tls config with bad ca", t, func() {
		cfg := TLSAutoConf{
			AutoTLSClientCAs: []string{"nope"},
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load ca file 0:")
	})
}

func makeFixtures() (syspool *x509.CertPool, custompool *x509.CertPool, cert tls.Certificate) {

	var err error

	ccad, err := os.ReadFile("fixtures/ca-cert.pem")
	if err != nil {
		panic(err)
	}
	public, private, err := tglib.ReadCertificatePEM("fixtures/cert-cert.pem", "fixtures/cert-key.pem", "")
	if err != nil {
		panic(err)
	}
	cert, err = tglib.ToTLSCertificate(public, private)
	if err != nil {
		panic(err)
	}

	cuspool := x509.NewCertPool()
	cuspool.AppendCertsFromPEM(ccad)

	syspool, err = x509.SystemCertPool()
	if err != nil {
		panic(err)
	}

	return syspool, cuspool, cert
}

func TestMongoConf(t *testing.T) {

	syspool, cuspool, tlscert := makeFixtures()

	Convey("disabled tls config", t, func() {
		cfg := MongoConf{
			MongoTLSDisable: true,
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldBeNil)
	})

	Convey("skipped tls config", t, func() {
		cfg := MongoConf{
			MongoTLSSkip: true,
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.InsecureSkipVerify, ShouldBeTrue)
	})

	Convey("tls config with system CA", t, func() {
		cfg := MongoConf{}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.RootCAs.Equal(syspool), ShouldBeTrue)
	})

	Convey("tls config with custom CA", t, func() {
		cfg := MongoConf{
			MongoTLSCA: "fixtures/ca-cert.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.RootCAs.Equal(cuspool), ShouldBeTrue)
	})

	Convey("tls config with certificate", t, func() {
		cfg := MongoConf{
			MongoTLSCertificate: "fixtures/cert-cert.pem",
			MongoTLSKey:         "fixtures/cert-key.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.Certificates[0].Certificate, ShouldResemble, tlscert.Certificate)
	})

	Convey("tls config with bad certificate", t, func() {
		cfg := MongoConf{
			MongoTLSCertificate: "fixtures/cert-key.pem",
			MongoTLSKey:         "fixtures/cert-key.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load client certificate:")
	})

	Convey("tls config with bad ca", t, func() {
		cfg := MongoConf{
			MongoTLSCA: "nope",
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load ca file:")
	})
}

func TestNATSConf(t *testing.T) {

	syspool, cuspool, tlscert := makeFixtures()

	Convey("disabled tls config", t, func() {
		cfg := NATSConf{
			NATSTLSDisable: true,
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldBeNil)
	})

	Convey("skipped tls config", t, func() {
		cfg := NATSConf{
			NATSTLSSkip: true,
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.InsecureSkipVerify, ShouldBeTrue)
	})

	Convey("tls config with system CA", t, func() {
		cfg := NATSConf{}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.RootCAs.Equal(syspool), ShouldBeTrue)
	})

	Convey("tls config with custom CA", t, func() {
		cfg := NATSConf{
			NATSTLSCA: "fixtures/ca-cert.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.RootCAs.Equal(cuspool), ShouldBeTrue)
	})

	Convey("tls config with certificate", t, func() {
		cfg := NATSConf{
			NATSTLSCertificate: "fixtures/cert-cert.pem",
			NATSTLSKey:         "fixtures/cert-key.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(err, ShouldBeNil)
		So(tlscfg, ShouldNotBeNil)
		So(tlscfg.Certificates[0].Certificate, ShouldResemble, tlscert.Certificate)
	})

	Convey("tls config with bad certificate", t, func() {
		cfg := NATSConf{
			NATSTLSCertificate: "fixtures/cert-key.pem",
			NATSTLSKey:         "fixtures/cert-key.pem",
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load client certificate:")
	})

	Convey("tls config with bad ca", t, func() {
		cfg := NATSConf{
			NATSTLSCA: "nope",
		}
		tlscfg, err := cfg.TLSConfig()
		So(tlscfg, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldStartWith, "unable to load ca file:")
	})
}

func TestGatewayConf_GWPrivateOverrides(t *testing.T) {
	tests := []struct {
		init  func(t *testing.T) *GatewayConf
		want1 map[elemental.Identity]bool
		name  string
	}{
		{
			name: "simple override",
			init: func(t *testing.T) *GatewayConf {
				return &GatewayConf{
					GWOverridePrivate: []string{"namespace:public", "authorization:private"},
				}
			},
			want1: map[elemental.Identity]bool{
				api.NamespaceIdentity:     false,
				api.AuthorizationIdentity: true,
			},
		},
		{
			name: "* public override",
			init: func(t *testing.T) *GatewayConf {
				return &GatewayConf{
					GWOverridePrivate: []string{"*:public"},
				}
			},
			want1: func() map[elemental.Identity]bool {
				m := map[elemental.Identity]bool{}
				for _, ident := range api.AllIdentities() {
					m[ident] = false
				}
				return m
			}(),
		},
		{
			name: "* private override",
			init: func(t *testing.T) *GatewayConf {
				return &GatewayConf{
					GWOverridePrivate: []string{"*:private"},
				}
			},
			want1: func() map[elemental.Identity]bool {
				m := map[elemental.Identity]bool{}
				for _, ident := range api.AllIdentities() {
					m[ident] = true
				}
				return m
			}(),
		},
		{
			name: "mixed private override",
			init: func(t *testing.T) *GatewayConf {
				return &GatewayConf{
					GWOverridePrivate: []string{"*:private", "namespace:public"},
				}
			},
			want1: func() map[elemental.Identity]bool {
				m := map[elemental.Identity]bool{}
				for _, ident := range api.AllIdentities() {
					m[ident] = true
				}
				m[api.NamespaceIdentity] = false
				return m
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver := tt.init(t)
			got1 := receiver.GWPrivateOverrides()

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("GatewayConf.GWPrivateOverrides got1 = %v, want1: %v", got1, tt.want1)
			}
		})
	}
}
