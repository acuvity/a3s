package samlissuer

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/tg/tglib"
)

func getECCert(subject pkix.Name, opts ...tglib.IssueOption) (*x509.Certificate, crypto.PrivateKey) {

	certBlock, keyBlock, err := tglib.Issue(subject, opts...)
	if err != nil {
		panic(err)
	}

	cert, err := tglib.ParseCertificate(pem.EncodeToMemory(certBlock))
	if err != nil {
		panic(err)
	}

	key, err := tglib.PEMToKey(keyBlock)
	if err != nil {
		panic(err)
	}

	return cert, key
}

func TestNew(t *testing.T) {

	checker, _ := netsafe.MakeChecker([]string{"11.0.0.1/32"}, nil)
	rm := netsafe.NewRequestMaker(checker)

	Convey("Calling New should work ", t, func() {
		src := api.NewSAMLSource()
		src.Name = "name"
		src.Namespace = "/ns"
		iss, _ := New(context.Background(), src, &saml2.AssertionInfo{}, rm)
		So(iss.(*samlIssuer).source, ShouldEqual, src)
		So(iss.Issue().Source.Type, ShouldEqual, "saml")
		So(iss.Issue().Source.Name, ShouldEqual, "name")
		So(iss.Issue().Source.Namespace, ShouldEqual, "/ns")
	})

	Convey("Calling New with a source and a modifier should work", t, func() {

		src := api.NewSAMLSource()
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			d, _ := json.Marshal([]string{"aa=aa", "bb=bb"})
			w.WriteHeader(http.StatusOK)
			w.Write(d) // nolint
		}))
		defer ts.Close()

		usercert1, userkey1 := getECCert(pkix.Name{})
		cab, _ := tglib.CertToPEM(ts.Certificate())
		certb, _ := tglib.CertToPEM(usercert1)
		keyb, _ := tglib.KeyToPEM(userkey1)
		src.Modifier = api.NewIdentityModifier()
		src.Modifier.CA = string(pem.EncodeToMemory(cab))
		src.Modifier.URL = ts.URL
		src.Modifier.Certificate = string(pem.EncodeToMemory(certb))
		src.Modifier.Key = string(pem.EncodeToMemory(keyb))
		src.IncludedKeys = []string{"aa", "bb"}

		iss, _ := New(context.Background(), src, &saml2.AssertionInfo{}, rm)
		So(iss.(*samlIssuer).source, ShouldEqual, src)
		So(iss.Issue().Identity, ShouldResemble, []string{"aa=aa", "bb=bb"})
	})

	Convey("Calling New with a source and a modifier with mussing tls info", t, func() {

		src := api.NewSAMLSource()
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			d, _ := json.Marshal([]string{"aa=aa", "bb=bb"})
			w.WriteHeader(http.StatusOK)
			w.Write(d) // nolint
		}))
		defer ts.Close()

		cab, _ := tglib.CertToPEM(ts.Certificate())
		src.Modifier = api.NewIdentityModifier()
		src.Modifier.CA = string(pem.EncodeToMemory(cab))
		src.Modifier.URL = ts.URL

		_, err := New(context.Background(), src, &saml2.AssertionInfo{}, rm)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `unable to prepare source modifier: unable to create certificate: could not read key data from bytes: ''`)
	})

	Convey("Calling New with a source and a modifier that returns an error", t, func() {

		src := api.NewSAMLSource()
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer ts.Close()

		usercert1, userkey1 := getECCert(pkix.Name{})
		cab, _ := tglib.CertToPEM(ts.Certificate())
		certb, _ := tglib.CertToPEM(usercert1)
		keyb, _ := tglib.KeyToPEM(userkey1)
		src.Modifier = api.NewIdentityModifier()
		src.Modifier.CA = string(pem.EncodeToMemory(cab))
		src.Modifier.URL = ts.URL
		src.Modifier.Certificate = string(pem.EncodeToMemory(certb))
		src.Modifier.Key = string(pem.EncodeToMemory(keyb))

		_, err := New(context.Background(), src, &saml2.AssertionInfo{}, rm)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `unable to call modifier: service returned an error: 403 Forbidden`)
	})
}

func Test_computeSAMLAssertion(t *testing.T) {
	type args struct {
		claims    *saml2.AssertionInfo
		translate bool
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1 []string
	}{
		{
			"standard with no exclusions",
			func(*testing.T) args {
				return args{
					&saml2.AssertionInfo{
						NameID: "coucou",
						Values: saml2.Values{
							"name": types.Attribute{
								Name: "name",
								Values: []types.AttributeValue{
									{
										Value: "jean",
									},
									{
										Value: "michel",
									},
								},
							},
							"email": types.Attribute{
								Name: "email",
								Values: []types.AttributeValue{
									{
										Value: "jean.michel@domain.com",
									},
								},
							},
						},
					},
					false,
				}
			},
			[]string{
				"email=jean.michel@domain.com",
				"name=jean",
				"name=michel",
				"nameid=coucou",
			},
		},
		{
			"ldap without translation",
			func(*testing.T) args {
				return args{
					&saml2.AssertionInfo{
						NameID: "coucou",
						Values: saml2.Values{
							"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": types.Attribute{
								Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
								Values: []types.AttributeValue{
									{
										Value: "jean",
									},
									{
										Value: "michel",
									},
								},
							},
							"http://schemas.microsoft.com/identity/claims/displayname": types.Attribute{
								Name: "http://schemas.microsoft.com/identity/claims/displayname",
								Values: []types.AttributeValue{
									{
										Value: "jean.michel@domain.com",
									},
								},
							},
							"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": types.Attribute{
								Name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
								Values: []types.AttributeValue{
									{
										Value: "a",
									},
									{
										Value: "b",
									},
								},
							},
						},
					},
					false,
				}
			},
			[]string{
				"http://schemas.microsoft.com/identity/claims/displayname=jean.michel@domain.com",
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups=a",
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups=b",
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name=jean",
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name=michel",
				"nameid=coucou",
			},
		},
		{
			"ldap with translation",
			func(*testing.T) args {
				return args{
					&saml2.AssertionInfo{
						NameID: "coucou",
						Values: saml2.Values{
							"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": types.Attribute{
								Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
								Values: []types.AttributeValue{
									{
										Value: "jean",
									},
									{
										Value: "michel",
									},
								},
							},
							"http://schemas.microsoft.com/identity/claims/displayname": types.Attribute{
								Name: "http://schemas.microsoft.com/identity/claims/displayname",
								Values: []types.AttributeValue{
									{
										Value: "jean.michel@domain.com",
									},
								},
							},
							"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": types.Attribute{
								Name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
								Values: []types.AttributeValue{
									{
										Value: "a",
									},
									{
										Value: "b",
									},
								},
							},
						},
					},
					true,
				}
			},
			[]string{
				"ad:displayname=jean.michel@domain.com",
				"ad:group=a",
				"ad:group=b",
				"ad:name=jean",
				"ad:name=michel",
				"nameid=coucou",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1 := computeSAMLAssertion(tArgs.claims, tArgs.translate)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("computeOIDClaims got1 = %v, want1: %v", got1, tt.want1)
			}
		})
	}
}
