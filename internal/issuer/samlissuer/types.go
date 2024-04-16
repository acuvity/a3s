package samlissuer

import "fmt"

// An ErrSAML represents an error that can occur
// during interactions with the SAML provider.
type ErrSAML struct {
	Err error
}

func (e ErrSAML) Error() string {
	return fmt.Sprintf("saml error: %s", e.Err)
}

// Unwrap returns the warped error.
func (e ErrSAML) Unwrap() error {
	return e.Err
}
