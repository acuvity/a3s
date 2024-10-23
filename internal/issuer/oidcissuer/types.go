package oidcissuer

import "fmt"

// An ErrOIDC represents an error that can occur
// during interactions with an OIDC server.
type ErrOIDC struct {
	Err error
}

func (e ErrOIDC) Error() string {
	return fmt.Sprintf("OIDC error: %s", e.Err)
}

// Unwrap returns the warped error.
func (e ErrOIDC) Unwrap() error {
	return e.Err
}
