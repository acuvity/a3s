package idp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authorizer"
)

// PeekBody prints the body of a response
// and puts it back into the body for later
// comsumption
func PeekBody(r *http.Response) {

	d, _ := io.ReadAll(r.Body)
	fmt.Println(string(d))
	r.Body = io.NopCloser(bytes.NewBuffer(d))
}

func MakeEventTriggeredRevocation(claims []string, namespace string, gracePeriod time.Duration) *api.Revocation {

	revoke := api.NewRevocation()

	revoke.CreateTime = time.Now()
	revoke.UpdateTime = revoke.CreateTime
	revoke.Namespace = namespace
	revoke.IssuedBefore = time.Now()
	revoke.ActiveAfter = time.Now().Add(gracePeriod)
	revoke.Subject = [][]string{claims}
	revoke.Expiration = time.Now().Add(365 * 24 * time.Hour)
	revoke.Propagate = true
	revoke.FlattenedSubject = authorizer.FlattenTags(revoke.Subject)

	return revoke
}
