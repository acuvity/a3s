package entraissuer

import "fmt"

// A Config holds the server-wide settings shared by all Entra sources.
type Config struct {
	// LoginURL is the Entra login endpoint, such as
	// https://login.microsoftonline.com, the tokens are issued by and the
	// tenant signing keys are fetched from.
	LoginURL string

	// APIAppID is the app ID of the API application, expected as aud.
	APIAppID string

	// NativeAppIDs are the app IDs of the native applications allowed as azp.
	NativeAppIDs []string

	// Scope is the scope of the API application required in scp.
	Scope string
}

// IsEnabled returns true if every setting is set.
func (c Config) IsEnabled() bool {
	return c.LoginURL != "" && c.APIAppID != "" && len(c.NativeAppIDs) != 0 && c.Scope != ""
}

// ErrEntra represents an error that happened
// during operation related to Entra.
type ErrEntra struct {
	Err error
}

func (e ErrEntra) Error() string {
	return fmt.Sprintf("entra error: %s", e.Err)
}

// Unwrap returns the wrapped error.
func (e ErrEntra) Unwrap() error {
	return e.Err
}

// entraJWT holds the claims of an Entra v2 access token used by the issuer.
type entraJWT struct {
	Version    string            `json:"ver"`
	TID        string            `json:"tid"`
	AZP        string            `json:"azp"`
	SCP        string            `json:"scp"`
	OID        string            `json:"oid"`
	UPN        string            `json:"upn"`
	Name       string            `json:"name"`
	Email      string            `json:"email"`
	Groups     []string          `json:"groups"`
	ClaimNames map[string]string `json:"_claim_names"`
}
