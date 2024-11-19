package oauth2provider

import (
	"net/http"

	"go.acuvity.ai/a3s/pkgs/api"
)

// A Provider is the interface used to retrieve OAuth2 provider
// specific information and turn that into claims.
type Provider interface {
	RetrieveClaims(*http.Client) ([]string, error)
	AuthURL() string
	TokenURL() string
}

// Get returns the provider for the given provider type.
// This function returns nil if no provider is available.
func Get(p api.OAuth2SourceProviderValue) Provider {

	switch p {
	case api.OAuth2SourceProviderGithub:
		return NewGithubProvider()
	case api.OAuth2SourceProviderGitlab:
		return NewGitlabProvider()
	case api.OAuth2SourceProviderHuggingface:
		return NewHuggingfaceProvider()
	case api.OAuth2SourceProviderGoogle:
		return NewGoogleProvider()
	}

	return nil
}
