package providers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestClient_AWSServiceRoleToken(t *testing.T) {

	Convey("When I call AWSServiceRoleToken (calling aws)", t, func() {

		tokenResponse := `{
                        "AccessKeyId": "x",
                        "SecretAccessKey": "y",
                        "Token": "z"
                        }`
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/iam/security-credentials/":
				fmt.Fprintf(w, `role`) // nolint: errcheck
			case "/iam/security-credentials/role":
				fmt.Fprint(w, tokenResponse) // nolint: errcheck
			default:
				fmt.Fprintln(w, "bad response") // nolint: errcheck
			}
		}))
		defer ts.Close()

		metadataPath = ts.URL + "/"
		token, err := AWSServiceRoleToken()

		Convey("Then err should be nil and the response should be correct", func() {
			So(err, ShouldBeNil)
			So(token, ShouldResemble, tokenResponse)
		})
	})

	Convey("When I call AWSServiceRoleToken  but can't retrieve role (comm error)", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusForbidden)
		}))
		defer ts.Close()

		metadataPath = ts.URL + "/"
		_, err := AWSServiceRoleToken()

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("When I call AWSServiceRoleToken without info (calling aws) but can't retrieve token (comm error)", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/iam/security-credentials/":
				fmt.Fprint(w, `role`) // nolint: errcheck
			default:
				http.Error(w, "nope", http.StatusForbidden)
			}
		}))
		defer ts.Close()

		metadataPath = ts.URL + "/"
		_, err := AWSServiceRoleToken()

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, `unable to retrieve token from magic url: 403 Forbidden`)
		})
	})
}
