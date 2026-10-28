package ciscoduo

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// emptySHA512 is the hex SHA-512 of the empty string. Duo v5 signatures hash
// the request body and the X-Duo-* headers; GET requests have neither.
var emptySHA512 = func() string {
	h := sha512.Sum512(nil)
	return hex.EncodeToString(h[:])
}()

// canonicalParams encodes the query parameters the way Duo expects: keys
// sorted, keys and values percent-encoded per RFC 3986 (space as %20, never +).
// The same string must be used both for the request URL and the signature.
func canonicalParams(params url.Values) string {

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	escape := func(s string) string {
		return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
	}

	parts := []string{}
	for _, k := range keys {
		vs := append([]string{}, params[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, escape(k)+"="+escape(v))
		}
	}

	return strings.Join(parts, "&")
}

// signRequest signs a body-less request using Duo's v5 (HMAC-SHA512) scheme
// and sets the Date and Authorization headers.
//
// The canonical string is the newline-joined list of: the date, the method,
// the lowercased host, the path, the canonical params, the SHA-512 of the body
// and the SHA-512 of the X-Duo-* headers.
func signRequest(r *http.Request, host string, path string, params string, ikey string, skey string, now time.Time) {

	date := now.UTC().Format(time.RFC1123Z)

	canon := strings.Join([]string{
		date,
		strings.ToUpper(r.Method),
		strings.ToLower(host),
		path,
		params,
		emptySHA512,
		emptySHA512,
	}, "\n")

	mac := hmac.New(sha512.New, []byte(skey))
	_, _ = mac.Write([]byte(canon))
	sig := hex.EncodeToString(mac.Sum(nil))

	r.Header.Set("Date", date)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(ikey+":"+sig)))
}
