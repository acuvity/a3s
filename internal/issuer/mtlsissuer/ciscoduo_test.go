package mtlsissuer

import (
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/internal/idp/ciscoduo"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/tg/tglib"
)

func TestHandleCiscoDuoAutologin(t *testing.T) {

	Convey("Given an MTLS source in CiscoDuo mode and a fake Duo Admin API", t, func() {

		var userQuery url.Values
		userStatus := "active"
		groupsBody := `{"stat":"OK","response":[{"group_id":"G1","name":"engineering"},{"group_id":"G2","name":""},{"group_id":"G3","name":"admins"}]}`

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin/v1/users":
				userQuery = r.URL.Query()
				_, _ = w.Write([]byte(`{"stat":"OK","response":[{"user_id":"DU1","username":"jane","email":"jane@org.com","realname":"Jane Doe","firstname":"Jane","lastname":"Doe","status":"` + userStatus + `"}]}`))
			case "/admin/v1/users/DU1/groups":
				_, _ = w.Write([]byte(groupsBody))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		Reset(ts.Close)

		checker, _ := netsafe.MakeChecker([]string{"11.0.0.1/32"}, nil)
		rm := netsafe.NewRequestMaker(checker)
		cmgr := ciscoduo.NewManager(ts.Client(), rm)

		cacert, cakey := getCA()
		block, _ := tglib.CertToPEM(cacert)
		usercert, _ := getECCert(
			pkix.Name{CommonName: "jane"},
			tglib.OptIssueSigner(cacert, cakey),
			tglib.OptIssueEmailAddresses([]string{"jane@org.com"}),
		)

		src := api.NewMTLSSource()
		src.Name = "duo"
		src.Namespace = "/my/ns"
		src.CA = string(pem.EncodeToMemory(block))
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeCiscoDuo
		src.CiscoDuoApplicationCredentials = &api.MTLSSourceCiscoDuo{
			APIHostname:    ts.Listener.Addr().String(),
			IntegrationKey: "ikey",
			SecretKey:      "skey",
		}

		Convey("When the principal field is Email and the user is active", func() {

			iss, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

			Convey("Then the email should be looked up as a username and the claims added", func() {
				So(err, ShouldBeNil)
				So(userQuery.Get("username"), ShouldEqual, "jane@org.com")
				So(userQuery.Has("email"), ShouldBeFalse)
				// The certificate claims (fingerprint, issuerchain, akid) are
				// appended after the Duo ones and vary per run.
				So(iss.Issue().Identity[:9], ShouldResemble, []string{
					"oid=DU1",
					"email=jane@org.com",
					"login=jane",
					"firstname=Jane",
					"lastname=Doe",
					"displayname=Jane Doe",
					"bypass=false",
					"group=engineering",
					"group=admins",
				})
			})
		})

		Convey("When the principal field is CommonName", func() {

			src.PrincipalUserX509Field = api.MTLSSourcePrincipalUserX509FieldCommonName
			_, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

			Convey("Then the user should be looked up by username", func() {
				So(err, ShouldBeNil)
				So(userQuery.Get("username"), ShouldEqual, "jane")
				So(userQuery.Has("email"), ShouldBeFalse)
			})
		})

		Convey("When the user is in bypass", func() {

			userStatus = "bypass"
			iss, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

			Convey("Then it should work with the bypass claim set", func() {
				So(err, ShouldBeNil)
				So(iss.Issue().Identity, ShouldContain, "bypass=true")
				So(iss.Issue().Identity, ShouldNotContain, "bypass=false")
			})
		})

		for _, status := range []string{"disabled", "locked out", "pending deletion"} {

			Convey("When the user is "+status, func() {

				userStatus = status
				_, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

				Convey("Then it should be forbidden", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldContainSubstring, "unable to perform ciscoduo additional claims retrieval")
					So(err.Error(), ShouldContainSubstring, "status: '"+status+"'")
				})
			})
		}

		for _, status := range []string{"Disabled", "disabled"} {

			Convey("When the user is member of a group with status "+status, func() {

				groupsBody = `{"stat":"OK","response":[{"group_id":"G1","name":"engineering","status":"Active"},{"group_id":"G2","name":"contractors","status":"` + status + `"}]}`
				_, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

				Convey("Then it should be forbidden", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldContainSubstring, "User is member of disabled group 'contractors'")
				})
			})
		}

		Convey("When the user is member of groups with status Active and Bypass", func() {

			groupsBody = `{"stat":"OK","response":[{"group_id":"G1","name":"engineering","status":"Active"},{"group_id":"G2","name":"admins","status":"Bypass"}]}`
			iss, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

			Convey("Then it should work with both group claims", func() {
				So(err, ShouldBeNil)
				So(iss.Issue().Identity, ShouldContain, "group=engineering")
				So(iss.Issue().Identity, ShouldContain, "group=admins")
			})
		})

		Convey("When the user has no groups", func() {

			groupsBody = `{"stat":"OK","response":[]}`
			iss, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

			Convey("Then it should work without group claims", func() {
				So(err, ShouldBeNil)
				for _, c := range iss.Issue().Identity {
					So(c, ShouldNotStartWith, "group=")
				}
			})
		})

		Convey("When the group retrieval fails", func() {

			groupsBody = `{"stat":"FAIL","code":42901,"message":"Too Many Requests"}`
			_, err := New(context.Background(), src, usercert, nil, nil, nil, cmgr, rm)

			Convey("Then it should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "Too Many Requests")
			})
		})
	})
}
