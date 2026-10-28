package ciscoduo

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
)

// newTestManager returns a Manager using the given client, whose request maker
// allows loopback (the only restricted network is a dummy one, mirroring
// mtls_test.go).
func newTestManager(client *http.Client) *Manager {
	checker, _ := netsafe.MakeChecker([]string{"11.0.0.1/32"}, nil)
	return NewManager(client, netsafe.NewRequestMaker(checker))
}

// verifySignature independently rebuilds the Duo v5 canonical string from the
// received request and checks the Authorization header against it.
func verifySignature(r *http.Request, ikey string, skey string) bool {

	q := r.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// keys are single valued in these tests.
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strings.ReplaceAll(url.QueryEscape(q.Get(k)), "+", "%20"))
	}

	empty := sha512.Sum512(nil)
	canon := strings.Join([]string{
		r.Header.Get("Date"),
		r.Method,
		strings.ToLower(r.Host),
		r.URL.EscapedPath(),
		strings.Join(parts, "&"),
		hex.EncodeToString(empty[:]),
		hex.EncodeToString(empty[:]),
	}, "\n")

	mac := hmac.New(sha512.New, []byte(skey))
	_, _ = mac.Write([]byte(canon))
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(ikey+":"+hex.EncodeToString(mac.Sum(nil))))

	return r.Header.Get("Authorization") == want
}

// newTestServer starts a fake Duo Admin API over TLS. Its client trusts the
// server certificate.
func newTestServer(handler http.HandlerFunc) (*httptest.Server, *api.MTLSSourceCiscoDuo) {

	ts := httptest.NewTLSServer(handler)

	return ts, &api.MTLSSourceCiscoDuo{
		APIHostname:    ts.Listener.Addr().String(),
		IntegrationKey: "DIWJ8X6AEYOR5OMC6TQ1",
		SecretKey:      "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep",
	}
}

func TestSignRequest(t *testing.T) {

	Convey("Given a request and a fixed time", t, func() {

		r, _ := http.NewRequest(http.MethodGet, "https://api-xxxxxxxx.duosecurity.com/admin/v1/users?username=root", nil)
		now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

		Convey("When I sign it", func() {
			signRequest(r, "API-xxxxxxxx.duosecurity.com", "/admin/v1/users", "username=root", "ikey", "skey", now)

			Convey("Then the Date header should be in RFC 2822 format", func() {
				So(r.Header.Get("Date"), ShouldEqual, "Mon, 26 Oct 2026 12:00:00 +0000")
			})

			Convey("Then the Authorization header should carry the v5 signature", func() {
				empty := sha512.Sum512(nil)
				canon := "Mon, 26 Oct 2026 12:00:00 +0000\nGET\napi-xxxxxxxx.duosecurity.com\n/admin/v1/users\nusername=root\n" +
					hex.EncodeToString(empty[:]) + "\n" + hex.EncodeToString(empty[:])
				mac := hmac.New(sha512.New, []byte("skey"))
				_, _ = mac.Write([]byte(canon))
				So(r.Header.Get("Authorization"), ShouldEqual, "Basic "+base64.StdEncoding.EncodeToString([]byte("ikey:"+hex.EncodeToString(mac.Sum(nil)))))
			})
		})
	})

	Convey("Given params needing encoding", t, func() {
		So(
			canonicalParams(url.Values{"username": {"jane doe"}, "email": {"jane+x@org.com"}}),
			ShouldEqual,
			"email=jane%2Bx%40org.com&username=jane%20doe",
		)
	})
}

func TestManagerGetUser(t *testing.T) {

	Convey("Given a manager and a users server", t, func() {

		var paths []string
		var gotQuery url.Values
		var signed bool
		var searchBody, idBody string
		var searchStatus, idStatus int

		ts, creds := newTestServer(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.EscapedPath())
			signed = verifySignature(r, "DIWJ8X6AEYOR5OMC6TQ1", "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep")
			if r.URL.Path == "/admin/v1/users" {
				gotQuery = r.URL.Query()
				w.WriteHeader(searchStatus)
				_, _ = w.Write([]byte(searchBody))
				return
			}
			w.WriteHeader(idStatus)
			_, _ = w.Write([]byte(idBody))
		})
		Reset(ts.Close)

		m := newTestManager(ts.Client())
		searchStatus = http.StatusOK
		searchBody = `{"stat":"OK","response":[{"user_id":"DU1","username":"jane","email":"jane@org.com","realname":"Jane Doe","firstname":"Jane","lastname":"Doe","status":"active"}]}`
		idStatus = http.StatusNotFound
		idBody = `{"stat":"FAIL","code":40401,"message":"Resource not found"}`

		Convey("When I call GetUser with a username", func() {
			u, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldBeNil)
			So(signed, ShouldBeTrue)
			So(paths, ShouldResemble, []string{"/admin/v1/users"})
			So(gotQuery.Get("username"), ShouldEqual, "jane")
			So(gotQuery.Has("email"), ShouldBeFalse)
			So(u.ID, ShouldEqual, "DU1")
			So(u.Username, ShouldEqual, "jane")
			So(u.Email, ShouldEqual, "jane@org.com")
			So(u.RealName, ShouldEqual, "Jane Doe")
			So(u.FirstName, ShouldEqual, "Jane")
			So(u.LastName, ShouldEqual, "Doe")
			So(u.Status, ShouldEqual, UserStatusActive)
		})

		Convey("When no username matches but the user ID does", func() {
			searchBody = `{"stat":"OK","response":[]}`
			idStatus = http.StatusOK
			idBody = `{"stat":"OK","response":{"user_id":"DU1","username":"jane","status":"active"}}`
			u, err := m.GetUser(context.Background(), creds, "DU1")
			So(err, ShouldBeNil)
			So(signed, ShouldBeTrue)
			So(paths, ShouldResemble, []string{"/admin/v1/users", "/admin/v1/users/DU1"})
			So(u.ID, ShouldEqual, "DU1")
			So(u.Username, ShouldEqual, "jane")
		})

		Convey("When the principal needs escaping to be tried as a user ID", func() {
			searchBody = `{"stat":"OK","response":[]}`
			_, err := m.GetUser(context.Background(), creds, "jane doe/x")
			So(err, ShouldNotBeNil)
			So(signed, ShouldBeTrue)
			So(paths, ShouldResemble, []string{"/admin/v1/users", "/admin/v1/users/jane%20doe%2Fx"})
		})

		Convey("When several users match the username", func() {
			searchBody = `{"stat":"OK","response":[{"user_id":"DU1","username":"jane","status":"active"},{"user_id":"DU2","username":"jane2","status":"active"}]}`
			_, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Multiple Duo users found with username 'jane'")
			So(paths, ShouldResemble, []string{"/admin/v1/users"})
		})

		Convey("When neither the username nor the user ID match", func() {
			searchBody = `{"stat":"OK","response":[]}`
			_, err := m.GetUser(context.Background(), creds, "nobody@org.com")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "No Duo user found with username or user ID 'nobody@org.com'")
		})

		Convey("When the user ID lookup fails with another error", func() {
			searchBody = `{"stat":"OK","response":[]}`
			idStatus = http.StatusUnauthorized
			idBody = `{"stat":"FAIL","code":40103,"message":"Invalid signature in request credentials"}`
			_, err := m.GetUser(context.Background(), creds, "DU1")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Invalid signature in request credentials")
		})

		Convey("When the principal is empty", func() {
			_, err := m.GetUser(context.Background(), creds, "")
			So(err, ShouldNotBeNil)
			So(paths, ShouldBeEmpty)
		})

		Convey("When Duo returns an error status", func() {
			searchStatus = http.StatusUnauthorized
			searchBody = `{"stat":"FAIL","code":40103,"message":"Invalid signature in request credentials"}`
			_, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Invalid signature in request credentials")
			So(paths, ShouldHaveLength, 1)
		})

		Convey("When Duo returns a FAIL envelope with a 200", func() {
			searchBody = `{"stat":"FAIL","code":40002,"message":"Invalid request parameters"}`
			_, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Invalid request parameters")
		})

		Convey("When the response is not JSON", func() {
			searchBody = `not json`
			_, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldNotBeNil)
		})

		Convey("When I call GetUser with nil credentials", func() {
			_, err := m.GetUser(context.Background(), nil, "jane")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestManagerGetMembership(t *testing.T) {

	Convey("Given a manager and a paginated groups server", t, func() {

		var offsets, limits []string
		var gotPath string
		allSigned := true
		var pages map[string]string

		ts, creds := newTestServer(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			gotPath = r.URL.Path
			offsets = append(offsets, q.Get("offset"))
			limits = append(limits, q.Get("limit"))
			allSigned = allSigned && verifySignature(r, "DIWJ8X6AEYOR5OMC6TQ1", "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(pages[q.Get("offset")]))
		})
		Reset(ts.Close)

		m := newTestManager(ts.Client())

		Convey("When I call GetMembership over multiple pages", func() {
			pages = map[string]string{
				"0":   `{"stat":"OK","response":[{"group_id":"G1","name":"group-one","status":"Active"},{"group_id":"G2","name":"group-two","status":"Disabled"}],"metadata":{"next_offset":500,"total_objects":3}}`,
				"500": `{"stat":"OK","response":[{"group_id":"G3","name":"group-three"}],"metadata":{"total_objects":3}}`,
			}

			groups, err := m.GetMembership(context.Background(), creds, &User{ID: "DU1"})
			So(err, ShouldBeNil)
			So(allSigned, ShouldBeTrue)
			So(gotPath, ShouldEqual, "/admin/v1/users/DU1/groups")
			So(len(groups), ShouldEqual, 3)
			So(groups[0].Name, ShouldEqual, "group-one")
			So(groups[1].Name, ShouldEqual, "group-two")
			So(groups[2].Name, ShouldEqual, "group-three")
			So(groups[0].Status, ShouldEqual, "Active")
			So(groups[1].Status, ShouldEqual, "Disabled")

			// pagination: 2 requests, the second one starting at next_offset.
			So(offsets, ShouldResemble, []string{"0", "500"})
			So(limits, ShouldResemble, []string{"500", "500"})
		})

		Convey("When the user has no groups", func() {
			pages = map[string]string{
				"0": `{"stat":"OK","response":[],"metadata":{"total_objects":0}}`,
			}

			groups, err := m.GetMembership(context.Background(), creds, &User{ID: "DU1"})
			So(err, ShouldBeNil)
			So(len(groups), ShouldEqual, 0)
			So(offsets, ShouldResemble, []string{"0"})
		})

		Convey("When next_offset does not move forward", func() {
			pages = map[string]string{
				"0": `{"stat":"OK","response":[{"group_id":"G1","name":"group-one"}],"metadata":{"next_offset":0}}`,
			}

			groups, err := m.GetMembership(context.Background(), creds, &User{ID: "DU1"})
			So(err, ShouldBeNil)
			So(len(groups), ShouldEqual, 1)
			So(offsets, ShouldResemble, []string{"0"})
		})

		Convey("When a page fails", func() {
			pages = map[string]string{
				"0":   `{"stat":"OK","response":[{"group_id":"G1","name":"group-one"}],"metadata":{"next_offset":500}}`,
				"500": `{"stat":"FAIL","code":42901,"message":"Too Many Requests"}`,
			}

			_, err := m.GetMembership(context.Background(), creds, &User{ID: "DU1"})
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Too Many Requests")
		})

		Convey("When I call GetMembership with nil credentials", func() {
			_, err := m.GetMembership(context.Background(), nil, &User{ID: "DU1"})
			So(err, ShouldNotBeNil)
		})
	})
}

func TestRetryAfter(t *testing.T) {

	Convey("Given the default retry waits", t, func() {

		Convey("Then a missing or invalid Retry-After should use the default wait", func() {
			So(retryAfter(""), ShouldEqual, duoRetryWait)
			So(retryAfter("abc"), ShouldEqual, duoRetryWait)
			So(retryAfter("-1"), ShouldEqual, duoRetryWait)
		})

		Convey("Then a valid Retry-After should be honored", func() {
			So(retryAfter("0"), ShouldEqual, 0)
			So(retryAfter("1"), ShouldEqual, time.Second)
		})

		Convey("Then a large Retry-After should be capped", func() {
			So(retryAfter("10"), ShouldEqual, duoRetryMaxWait)
		})
	})
}

func TestManagerRateLimitRetry(t *testing.T) {

	Convey("Given a manager and a users server that can rate limit", t, func() {

		var statuses []int
		var requests int
		allSigned := true

		ts, creds := newTestServer(func(w http.ResponseWriter, r *http.Request) {
			allSigned = allSigned && verifySignature(r, "DIWJ8X6AEYOR5OMC6TQ1", "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep")
			status := statuses[requests]
			requests++
			w.WriteHeader(status)
			if status == http.StatusTooManyRequests {
				_, _ = w.Write([]byte(`{"stat":"FAIL","code":42901,"message":"Too Many Requests"}`))
				return
			}
			if status == http.StatusInternalServerError {
				_, _ = w.Write([]byte(`{"stat":"FAIL","code":50000,"message":"Internal Server Error"}`))
				return
			}
			_, _ = w.Write([]byte(`{"stat":"OK","response":[{"user_id":"DU1","username":"jane","status":"active"}]}`))
		})

		origWait := duoRetryWait
		duoRetryWait = 10 * time.Millisecond
		Reset(func() {
			ts.Close()
			duoRetryWait = origWait
		})

		m := newTestManager(ts.Client())

		Convey("When the first request is rate limited and the retry succeeds", func() {
			statuses = []int{http.StatusTooManyRequests, http.StatusOK}
			u, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldBeNil)
			So(u.ID, ShouldEqual, "DU1")
			So(requests, ShouldEqual, 2)
			So(allSigned, ShouldBeTrue)
		})

		Convey("When both requests are rate limited", func() {
			statuses = []int{http.StatusTooManyRequests, http.StatusTooManyRequests}
			_, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "429")
			So(err.Error(), ShouldContainSubstring, "Too Many Requests")
			So(requests, ShouldEqual, 2)
		})

		Convey("When the request fails with another error", func() {
			statuses = []int{http.StatusInternalServerError, http.StatusOK}
			_, err := m.GetUser(context.Background(), creds, "jane")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "500")
			So(requests, ShouldEqual, 1)
		})

		Convey("When the context is canceled while waiting to retry", func() {
			statuses = []int{http.StatusTooManyRequests, http.StatusOK}
			duoRetryWait = 5 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()

			start := time.Now()
			_, err := m.GetUser(ctx, creds, "jane")
			So(err, ShouldNotBeNil)
			So(time.Since(start), ShouldBeLessThan, time.Second)
			So(requests, ShouldEqual, 1)
		})
	})
}
