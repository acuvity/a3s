package oauth

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestOAuthIssuer(t *testing.T) {

	Convey("Given an a3s issuer", t, func() {

		for _, issuer := range []string{"https://a3s.test", "https://a3s.test/prefix"} {
			for _, namespace := range []string{"/", "/orgs/acme", "/orgs/acme/apps"} {

				oauthIssuer, err := IssuerFor(issuer, namespace)
				So(err, ShouldBeNil)

				back, ok := A3SIssuer(oauthIssuer, namespace)
				So(ok, ShouldBeTrue)
				So(back, ShouldEqual, issuer)
			}
		}
	})

	Convey("The OAuth issuer of a namespace should be the expected one", t, func() {

		issuer, err := IssuerFor("https://a3s.test", "/orgs/acme")
		So(err, ShouldBeNil)
		So(issuer, ShouldEqual, "https://a3s.test/oauth/L29yZ3MvYWNtZQ")

		issuer, err = IssuerFor("https://a3s.test", "/")
		So(err, ShouldBeNil)
		So(issuer, ShouldEqual, "https://a3s.test/oauth")
	})

	Convey("The a3s issuer of the OAuth issuer of another namespace should not be found", t, func() {

		_, ok := A3SIssuer("https://a3s.test/oauth/L29yZ3Mvb3RoZXI", "/orgs/acme")
		So(ok, ShouldBeFalse)

		_, ok = A3SIssuer("https://a3s.test", "/orgs/acme")
		So(ok, ShouldBeFalse)
	})

	Convey("An invalid issuer should fail", t, func() {

		_, err := IssuerFor("://bad", "/")
		So(err, ShouldNotBeNil)
	})
}
