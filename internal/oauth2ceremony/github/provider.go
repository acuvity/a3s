package oauth2provider

import "net/http"

// A Provider is the interface used to retrieve OAuth2 provider
// specific information and turn that into claims.
type Provider interface {
	RetrieveClaims(*http.Client) ([]string, error)
	AuthURL() string
	TokenURL() string
}
