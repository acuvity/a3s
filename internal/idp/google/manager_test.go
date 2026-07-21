package google

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
)

// rsaKeyPEM returns a fresh PKCS8 RSA private key in PEM form, suitable for
// signing the RS256 service account assertion.
func rsaKeyPEM() string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// newTestManager returns a Manager whose request maker allows loopback (the
// only restricted network is a dummy one, mirroring mtls_test.go).
func newTestManager() *Manager {
	checker, _ := netsafe.MakeChecker([]string{"11.0.0.1/32"}, nil)
	return NewManager(&http.Client{}, netsafe.NewRequestMaker(checker))
}

func TestManagerGetAccessToken(t *testing.T) {

	Convey("Given a manager and a token server", t, func() {

		var gotGrant, gotAssertion string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotGrant = r.PostFormValue("grant_type")
			gotAssertion = r.PostFormValue("assertion")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"the-token"}`))
		}))

		orig := googleTokenURL
		googleTokenURL = ts.URL
		Reset(func() {
			ts.Close()
			googleTokenURL = orig
		})

		m := newTestManager()
		creds := &api.MTLSSourceGoogle{
			ClientEmail:  "a3s@proj.iam.gserviceaccount.com",
			PrivateKey:   rsaKeyPEM(),
			PrivateKeyID: "kid-1",
			Subject:      "admin@org.com",
		}

		Convey("When I call GetAccessToken with valid credentials", func() {
			tok, err := m.GetAccessToken(context.Background(), creds)
			So(err, ShouldBeNil)
			So(tok, ShouldNotBeNil)
			So(tok.AccessToken, ShouldEqual, "the-token")
			So(gotGrant, ShouldEqual, "urn:ietf:params:oauth:grant-type:jwt-bearer")
			So(gotAssertion, ShouldNotBeEmpty)
		})

		Convey("When I call GetAccessToken with nil credentials", func() {
			_, err := m.GetAccessToken(context.Background(), nil)
			So(err, ShouldNotBeNil)
		})

		Convey("When I call GetAccessToken with an invalid private key", func() {
			creds.PrivateKey = "not a pem"
			_, err := m.GetAccessToken(context.Background(), creds)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestManagerGetUser(t *testing.T) {

	Convey("Given a manager and a directory server", t, func() {

		var gotPath, gotAuth string
		status := http.StatusOK
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"id":"123","primaryEmail":"jane@org.com","suspended":false,"name":{"givenName":"Jane","familyName":"Doe","fullName":"Jane Doe"}}`))
		}))

		orig := googleDirectoryBaseURL
		googleDirectoryBaseURL = ts.URL
		Reset(func() {
			ts.Close()
			googleDirectoryBaseURL = orig
		})

		m := newTestManager()

		Convey("When I call GetUser", func() {
			u, err := m.GetUser(context.Background(), &AccessToken{AccessToken: "tok"}, "jane@org.com")
			So(err, ShouldBeNil)
			So(u.ID, ShouldEqual, "123")
			So(u.PrimaryEmail, ShouldEqual, "jane@org.com")
			So(u.Name.GivenName, ShouldEqual, "Jane")
			So(u.Name.FamilyName, ShouldEqual, "Doe")
			So(u.Name.FullName, ShouldEqual, "Jane Doe")
			So(gotPath, ShouldEqual, "/admin/directory/v1/users/jane@org.com")
			So(gotAuth, ShouldEqual, "Bearer tok")
		})

		Convey("When the server returns a non-200 status", func() {
			status = http.StatusForbidden
			_, err := m.GetUser(context.Background(), &AccessToken{AccessToken: "tok"}, "jane@org.com")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestManagerGetMembership(t *testing.T) {

	Convey("Given a manager and a paginated groups server", t, func() {

		var pageTokens, userKeys []string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			pageTokens = append(pageTokens, q.Get("pageToken"))
			userKeys = append(userKeys, q.Get("userKey"))
			w.WriteHeader(http.StatusOK)
			if q.Get("pageToken") == "" {
				_, _ = w.Write([]byte(`{"groups":[{"id":"1","email":"g1@org.com","name":"group-one"},{"id":"2","email":"g2@org.com","name":"group-two"}],"nextPageToken":"PAGE2"}`))
			} else {
				_, _ = w.Write([]byte(`{"groups":[{"id":"3","email":"g3@org.com","name":"group-three"}]}`))
			}
		}))

		orig := googleDirectoryBaseURL
		googleDirectoryBaseURL = ts.URL
		Reset(func() {
			ts.Close()
			googleDirectoryBaseURL = orig
		})

		m := newTestManager()

		Convey("When I call GetMembership over multiple pages", func() {
			members, err := m.GetMembership(context.Background(), &AccessToken{AccessToken: "tok"}, &User{PrimaryEmail: "jane@org.com"})
			So(err, ShouldBeNil)
			So(len(members), ShouldEqual, 3)
			So(members[0].Name, ShouldEqual, "group-one")
			So(members[1].Name, ShouldEqual, "group-two")
			So(members[2].Name, ShouldEqual, "group-three")

			// pagination: 2 requests, the second one carrying the nextPageToken.
			So(len(pageTokens), ShouldEqual, 2)
			So(pageTokens[0], ShouldEqual, "")
			So(pageTokens[1], ShouldEqual, "PAGE2")
			So(userKeys[0], ShouldEqual, "jane@org.com")
		})
	})
}
