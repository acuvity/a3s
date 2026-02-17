package netsafe

import (
	"net/http"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestRestrictedIP(t *testing.T) {

	checker, err := MakeChecker(IANAPrivateNetworks, []string{"192.168.2.0/24", "192.168.1.14/32"})

	Convey("Given I have an IANA checker", t, func() {

		Convey("localhost is restricted", func() {
			err := checker("localhost")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "restricted IP: restricted IP '127.0.0.1'")
		})

		Convey("192.168.1.13 is restricted", func() {
			err = checker("192.168.1.13")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "restricted IP: restricted IP '192.168.1.13'")
		})

		Convey("192.168.1.13:1234 is restricted", func() {
			err = checker("192.168.1.13:1234")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "restricted IP: restricted IP '192.168.1.13'")
		})

		Convey("192.168.1.13:1234 is restricted again (cached)", func() {
			err = checker("192.168.1.13:1234")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "restricted IP: restricted IP '192.168.1.13'")
		})

		Convey("192.168.2.13:1234 is ignored", func() {
			err = checker("192.168.2.13:1234")
			So(err, ShouldBeNil)
		})

		Convey("192.168.1.14:1234 is ignored", func() {
			err = checker("192.168.1.14:1234")
			So(err, ShouldBeNil)
		})

		Convey("10.0.1.34 is restricted", func() {
			err = checker("10.0.1.34")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "restricted IP: restricted IP '10.0.1.34'")
		})

		Convey("10.0.1.34 is restricted again (cached)", func() {
			err = checker("10.0.1.34")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "restricted IP: restricted IP '10.0.1.34'")
		})

		Convey("67.98.1.3 is not restricted", func() {
			err = checker("67.98.1.3")
			So(err, ShouldBeNil)
		})

		Convey("bad IP should fail the call", func() {
			err = checker("this-is-not-a-host-that-matches-anything-hopefully")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldStartWith, "unable to lookup host 'this-is-not-a-host-that-matches-anything-hopefully':")
		})

		Convey("Good host should work", func() {
			err = checker("google.com")
			So(err, ShouldBeNil)
		})

		Convey("Good host should work again (cached)", func() {
			err = checker("google.com")
			So(err, ShouldBeNil)
		})
	})
}

func TestMakeNoloRequest(t *testing.T) {

	Convey("When I create a nolo request maker without passing a checker", t, func() {

		maker := NewRequestMaker(nil)

		r, err := maker(t.Context(), http.MethodPost, "https://127.0.0.1:8080/toto", nil)
		So(r, ShouldBeNil)
		So(err.Error(), ShouldEqual, "unacceptable url hostname: restricted IP: restricted IP '127.0.0.1'")

		r, err = maker(t.Context(), http.MethodPost, "https://localhost:8080/toto", nil)
		So(r, ShouldBeNil)
		So(err.Error(), ShouldEqual, "unacceptable url hostname: restricted IP: restricted IP '127.0.0.1'")

		r, err = maker(t.Context(), http.MethodPost, "https://34.34.34.34:8080/toto", nil)
		So(r, ShouldNotBeNil)
		So(err, ShouldBeNil)

		r, err = maker(t.Context(), http.MethodPost, "https://google.com/toto", nil)
		So(r, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})
}
