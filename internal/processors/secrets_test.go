package processors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/elemental"
)

const testPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"

// shouldBeValidationErrorOn checks that the actual error is a 422 elemental
// error about the expected attribute, as rendered to the client.
func shouldBeValidationErrorOn(actual any, expected ...any) string {

	err, _ := actual.(error)
	if err == nil {
		return "expected an error, got nil"
	}

	// This is what bahamut does with the error returned by a processor.
	errs := elemental.NewErrors(crud.ErrPreWriteHook{Err: err})
	if errs.Code() != http.StatusUnprocessableEntity {
		return "expected a 422 error, got: " + errs.Error()
	}

	var attr string
	switch d := errs[0].Data.(type) {
	case map[string]string:
		attr = d["attribute"]
	case map[string]any:
		attr, _ = d["attribute"].(string)
	}

	if attr != expected[0].(string) {
		return "expected error on attribute '" + expected[0].(string) + "', got '" + attr + "'"
	}

	return ""
}

func TestValidateSimpleSourceSecrets(t *testing.T) {

	type testCase struct {
		name      string
		attribute string
		make      func(secret string) elemental.AttributeSpecifiable
		secret    func(obj elemental.AttributeSpecifiable) string
		validate  func(obj elemental.AttributeSpecifiable) error
	}

	cases := []testCase{
		{
			name:      "LDAPSource",
			attribute: "bindPassword",
			make: func(secret string) elemental.AttributeSpecifiable {
				o := api.NewLDAPSource()
				o.BindPassword = secret
				return o
			},
			secret:   func(o elemental.AttributeSpecifiable) string { return o.(*api.LDAPSource).BindPassword },
			validate: func(o elemental.AttributeSpecifiable) error { return validateLDAPSourceSecrets(o.(*api.LDAPSource)) },
		},
		{
			name:      "OAuth2Source",
			attribute: "clientSecret",
			make: func(secret string) elemental.AttributeSpecifiable {
				o := api.NewOAuth2Source()
				o.ClientSecret = secret
				return o
			},
			secret: func(o elemental.AttributeSpecifiable) string { return o.(*api.OAuth2Source).ClientSecret },
			validate: func(o elemental.AttributeSpecifiable) error {
				return validateOAuth2SourceSecrets(o.(*api.OAuth2Source))
			},
		},
		{
			name:      "OIDCSource",
			attribute: "clientSecret",
			make: func(secret string) elemental.AttributeSpecifiable {
				o := api.NewOIDCSource()
				o.ClientSecret = secret
				return o
			},
			secret:   func(o elemental.AttributeSpecifiable) string { return o.(*api.OIDCSource).ClientSecret },
			validate: func(o elemental.AttributeSpecifiable) error { return validateOIDCSourceSecrets(o.(*api.OIDCSource)) },
		},
	}

	for _, tc := range cases {

		Convey("Given a "+tc.name, t, func() {

			Convey("When the secret is empty", func() {
				err := tc.validate(tc.make(""))
				So(err, shouldBeValidationErrorOn, tc.attribute)
			})

			Convey("When the secret is set", func() {
				So(tc.validate(tc.make(testPEM)), ShouldBeNil)
			})

			Convey("When the secret is omitted on update and backported from the stored object", func() {
				stored := tc.make(testPEM)
				incoming := tc.make("")
				elemental.BackportUnexposedFields(stored, incoming)
				So(tc.validate(incoming), ShouldBeNil)
				So(tc.secret(incoming), ShouldEqual, testPEM)
			})

			Convey("When the secret is changed on update", func() {
				stored := tc.make(testPEM)
				incoming := tc.make(testPEM + "\n")
				elemental.BackportUnexposedFields(stored, incoming)
				So(tc.validate(incoming), ShouldBeNil)
				So(tc.secret(incoming), ShouldEqual, testPEM+"\n")
			})
		})
	}
}

// makeTestCertKey returns a self-signed certificate and its private key, PEM encoded.
func makeTestCertKey(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}

func TestValidateHTTPSourceSecrets(t *testing.T) {

	cert1, key1 := makeTestCertKey(t)
	cert2, key2 := makeTestCertKey(t)

	makeSrc := func(cert string, key string) *api.HTTPSource {
		src := api.NewHTTPSource()
		src.Certificate = cert
		src.Key = key
		return src
	}

	Convey("Given a HTTPSource", t, func() {

		Convey("When the key is empty", func() {
			So(validateHTTPSourceSecrets(makeSrc(cert1, "")), shouldBeValidationErrorOn, "key")
		})

		Convey("When the key matches the certificate", func() {
			So(validateHTTPSourceSecrets(makeSrc(cert1, key1)), ShouldBeNil)
		})

		Convey("When the key is not a valid PEM", func() {
			So(validateHTTPSourceSecrets(makeSrc(cert1, "not a pem")), shouldBeValidationErrorOn, "key")
		})

		Convey("When the key is a valid PEM but not a key", func() {
			So(validateHTTPSourceSecrets(makeSrc(cert1, testPEM)), shouldBeValidationErrorOn, "key")
		})

		Convey("When the key does not match the certificate", func() {
			So(validateHTTPSourceSecrets(makeSrc(cert1, key2)), shouldBeValidationErrorOn, "key")
		})

		Convey("When the key is omitted on update and backported from the stored object", func() {
			stored := makeSrc(cert1, key1)
			incoming := makeSrc(cert1, "")
			elemental.BackportUnexposedFields(stored, incoming)
			So(validateHTTPSourceSecrets(incoming), ShouldBeNil)
			So(incoming.Key, ShouldEqual, key1)
		})

		Convey("When the certificate and key are both changed on update", func() {
			stored := makeSrc(cert1, key1)
			incoming := makeSrc(cert2, key2)
			elemental.BackportUnexposedFields(stored, incoming)
			So(validateHTTPSourceSecrets(incoming), ShouldBeNil)
			So(incoming.Key, ShouldEqual, key2)
		})

		Convey("When only the certificate is changed on update, the stored key is checked against it", func() {
			stored := makeSrc(cert1, key1)
			incoming := makeSrc(cert2, "")
			elemental.BackportUnexposedFields(stored, incoming)
			So(incoming.Key, ShouldEqual, key1)
			So(validateHTTPSourceSecrets(incoming), shouldBeValidationErrorOn, "key")
		})
	})
}

func TestValidateMTLSSourceSecrets(t *testing.T) {

	type testCase struct {
		mode      api.MTLSSourceClaimsRetrievalModeValue
		attribute string
		set       func(src *api.MTLSSource, secret string)
		secret    func(src *api.MTLSSource) string
	}

	cases := []testCase{
		{
			mode:      api.MTLSSourceClaimsRetrievalModeCiscoDuo,
			attribute: "ciscoDuoApplicationCredentials/secretKey",
			set: func(src *api.MTLSSource, secret string) {
				src.CiscoDuoApplicationCredentials = api.NewMTLSSourceCiscoDuo()
				src.CiscoDuoApplicationCredentials.SecretKey = secret
			},
			secret: func(src *api.MTLSSource) string { return src.CiscoDuoApplicationCredentials.SecretKey },
		},
		{
			mode:      api.MTLSSourceClaimsRetrievalModeEntra,
			attribute: "entraApplicationCredentials/clientSecret",
			set: func(src *api.MTLSSource, secret string) {
				src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
				src.EntraApplicationCredentials.ClientSecret = secret
			},
			secret: func(src *api.MTLSSource) string { return src.EntraApplicationCredentials.ClientSecret },
		},
		{
			mode:      api.MTLSSourceClaimsRetrievalModeGoogleWorkspace,
			attribute: "googleWorkspaceApplicationCredentials/privateKey",
			set: func(src *api.MTLSSource, secret string) {
				src.GoogleWorkspaceApplicationCredentials = api.NewMTLSSourceGoogle()
				src.GoogleWorkspaceApplicationCredentials.PrivateKey = secret
			},
			secret: func(src *api.MTLSSource) string { return src.GoogleWorkspaceApplicationCredentials.PrivateKey },
		},
		{
			mode:      api.MTLSSourceClaimsRetrievalModeOkta,
			attribute: "oktaApplicationCredentials/privateKey",
			set: func(src *api.MTLSSource, secret string) {
				src.OktaApplicationCredentials = api.NewMTLSSourceOkta()
				src.OktaApplicationCredentials.PrivateKey = secret
			},
			secret: func(src *api.MTLSSource) string { return src.OktaApplicationCredentials.PrivateKey },
		},
	}

	makeSrc := func(mode api.MTLSSourceClaimsRetrievalModeValue, set func(*api.MTLSSource, string), secret string) *api.MTLSSource {
		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = mode
		set(src, secret)
		return src
	}

	for _, tc := range cases {

		Convey("Given a MTLSSource in mode "+string(tc.mode), t, func() {

			Convey("When the secret is empty", func() {
				src := makeSrc(tc.mode, tc.set, "")
				insertEntraSecrets(src, nil)
				So(validateMTLSSourceSecrets(src), shouldBeValidationErrorOn, tc.attribute)
			})

			Convey("When the credentials are nil", func() {
				src := api.NewMTLSSource()
				src.ClaimsRetrievalMode = tc.mode
				So(validateMTLSSourceSecrets(src), shouldBeValidationErrorOn, tc.attribute)
			})

			Convey("When the secret is set", func() {
				src := makeSrc(tc.mode, tc.set, testPEM)
				insertEntraSecrets(src, nil)
				So(validateMTLSSourceSecrets(src), ShouldBeNil)
			})

			Convey("When the secret is omitted on update and backported from the stored object", func() {
				stored := makeSrc(tc.mode, tc.set, testPEM)
				incoming := makeSrc(tc.mode, tc.set, "")
				elemental.BackportUnexposedFields(stored, incoming)
				insertEntraSecrets(incoming, stored)
				So(validateMTLSSourceSecrets(incoming), ShouldBeNil)
				So(tc.secret(incoming), ShouldEqual, testPEM)
			})
		})
	}

	Convey("Given a stored Okta MTLSSource updated to Entra without a client secret", t, func() {
		stored := makeSrc(api.MTLSSourceClaimsRetrievalModeOkta, cases[3].set, testPEM)
		incoming := makeSrc(api.MTLSSourceClaimsRetrievalModeEntra, cases[1].set, "")
		elemental.BackportUnexposedFields(stored, incoming)
		insertEntraSecrets(incoming, stored)
		So(validateMTLSSourceSecrets(incoming), shouldBeValidationErrorOn, "entraApplicationCredentials/clientSecret")
	})

	Convey("Given an Entra MTLSSource with graph events enabled and a client secret", t, func() {
		src := makeSrc(api.MTLSSourceClaimsRetrievalModeEntra, cases[1].set, "secret")
		src.EntraApplicationCredentials.GraphEventsEnabled = true
		insertEntraSecrets(src, nil)
		So(validateMTLSSourceSecrets(src), ShouldBeNil)
		So(src.EntraApplicationCredentials.ClientSecret, ShouldEqual, "secret")
		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldNotBeEmpty)
	})

	Convey("Given a X509 MTLSSource without credentials", t, func() {
		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeX509
		So(validateMTLSSourceSecrets(src), ShouldBeNil)
	})

	Convey("Given an Okta MTLSSource with an invalid PEM private key", t, func() {
		src := makeSrc(api.MTLSSourceClaimsRetrievalModeOkta, cases[3].set, "not a pem")
		So(validateMTLSSourceSecrets(src), ShouldBeNil)
		So(insertTLSReferences(src), shouldBeValidationErrorOn, "oktaApplicationCredentials/privateKey")
	})

	Convey("Given a GoogleWorkspace MTLSSource with an invalid PEM private key", t, func() {
		src := makeSrc(api.MTLSSourceClaimsRetrievalModeGoogleWorkspace, cases[2].set, "not a pem")
		So(validateMTLSSourceSecrets(src), ShouldBeNil)
		So(insertTLSReferences(src), shouldBeValidationErrorOn, "googleWorkspaceApplicationCredentials/privateKey")
	})
}
