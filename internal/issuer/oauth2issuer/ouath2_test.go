package oauth2issuer

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

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
		src := api.NewOAuth2Source()
		src.Name = "name"
		src.Namespace = "/ns"
		iss, _ := New(context.Background(), src, []string{"hello=world"}, rm)
		So(iss.(*oauth2Issuer).source, ShouldEqual, src)
		So(iss.Issue().Source.Type, ShouldEqual, "oauth2")
		So(iss.Issue().Source.Name, ShouldEqual, "name")
		So(iss.Issue().Source.Namespace, ShouldEqual, "/ns")
	})

	Convey("Calling New with a source and a modifier should work", t, func() {

		src := api.NewOAuth2Source()
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

		iss, _ := New(context.Background(), src, []string{"hello=world"}, rm)
		So(iss.(*oauth2Issuer).source, ShouldEqual, src)
		So(iss.Issue().Identity, ShouldResemble, []string{"aa=aa", "bb=bb"})
	})

	Convey("Calling New with a source and a modifier with mussing tls info", t, func() {

		src := api.NewOAuth2Source()
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

		_, err := New(context.Background(), src, []string{"hello=world"}, rm)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `unable to prepare source modifier: unable to create certificate: could not read key data from bytes: ''`)
	})

	Convey("Calling New with a source and a modifier that returns an error", t, func() {

		src := api.NewOAuth2Source()
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

		_, err := New(context.Background(), src, []string{"hello=world"}, rm)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `unable to call modifier: service returned an error: 403 Forbidden`)
	})
}
