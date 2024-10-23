package oauth2issuer

import "fmt"

// An ErrOAuth2 represents an error that can occur
// during interactions with an OAuth2 server.
type ErrOAuth2 struct {
	Err error
}

func (e ErrOAuth2) Error() string {
	return fmt.Sprintf("oauth2 error: %s", e.Err)
}

// Unwrap returns the warped error.
func (e ErrOAuth2) Unwrap() error {
	return e.Err
}
