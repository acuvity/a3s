package utils

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// PeekBody prints the body of a response
// and puts it back into the body for later
// comsumption
func PeekBody(r *http.Response) {

	d, _ := io.ReadAll(r.Body)
	fmt.Println(string(d))
	r.Body = io.NopCloser(bytes.NewBuffer(d))
}
