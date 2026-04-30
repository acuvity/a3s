package oauthserver

import "errors"

var (
	ErrOAuthApplicationDisabled = errors.New("oauth application is disabled")
	ErrAuthorizeContextExpired  = errors.New("authorize request expired")
	ErrAuthorizationCodeExpired = errors.New("authorization code expired")
	ErrAuthorizationCodeUsed    = errors.New("authorization code has already been used")
	ErrNotFound                 = errors.New("not found")
)

type protocolError struct {
	code        string
	description string
}

func (e *protocolError) Error() string {
	return e.description
}

func newProtocolError(code string, description string) error {
	return &protocolError{
		code:        code,
		description: description,
	}
}

func protocolErrorDetails(err error) (string, string, bool) {
	var pErr *protocolError
	if errors.As(err, &pErr) {
		return pErr.code, pErr.description, true
	}

	return "", "", false
}
