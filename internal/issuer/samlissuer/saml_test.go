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

	Convey("Calling New should work ", t, func() {
		src := api.NewSAMLSource()
		src.Name = "name"
		src.Namespace = "/ns"
		iss, _ := New(context.Background(), src, &saml2.AssertionInfo{})
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

		iss, _ := New(context.Background(), src, &saml2.AssertionInfo{})
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

		_, err := New(context.Background(), src, &saml2.AssertionInfo{})
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

		_, err := New(context.Background(), src, &saml2.AssertionInfo{})
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `unable to call modifier: service returned an error: 403 Forbidden`)
	})
}

func Test_computeSAMLAssertion(t *testing.T) {
	type args struct {
		claims *saml2.AssertionInfo
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1 []string
	}{
		{
			"standard",
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
			"lowercase email claims only",
			func(*testing.T) args {
				return args{
					&saml2.AssertionInfo{
						NameID: "coucou",
						Values: saml2.Values{
							"fullname": types.Attribute{
								Name: "fullname",
								Values: []types.AttributeValue{
									{
										Value: "Jean Michel",
									},
								},
							},
							"email": types.Attribute{
								Name: "email",
								Values: []types.AttributeValue{
									{
										Value: "Jean.Michel@domain.com",
									},
								},
							},
						},
					},
				}
			},
			[]string{
				"email=jean.michel@domain.com",
				"fullname=Jean Michel",
				"nameid=coucou",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1 := computeSAMLAssertion(tArgs.claims)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("computeOIDClaims got1 = %v, want1: %v", got1, tt.want1)
			}
		})
	}
}
