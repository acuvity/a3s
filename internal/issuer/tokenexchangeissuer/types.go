package tokenexchangeissuer

import "fmt"

// ErrTokenExchange represents an error that happened
// during operation related to token exchange.
type ErrTokenExchange struct {
	Err error
}

func (e ErrTokenExchange) Error() string {
	return fmt.Sprintf("token exchange error: %s", e.Err)
}

// Unwrap returns the wrapped error.
func (e ErrTokenExchange) Unwrap() error {
	return e.Err
}
