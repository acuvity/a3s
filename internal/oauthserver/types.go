package oauthserver

import (
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
)

// AuthorizeRequest contains normalized authorization request data after
// validation.
type AuthorizeRequest struct {
	Namespace           string   `json:"namespace"`
	ClientID            string   `json:"clientid"`
	RedirectURI         string   `json:"redirecturi"`
	RedirectURIIncluded bool     `json:"redirecturiincluded"`
	ScopeIncluded       bool     `json:"scopeincluded"`
	RequestedScopes     []string `json:"requestedscopes,omitempty"`
	State               string   `json:"state,omitempty"`
	CodeChallenge       string   `json:"codechallenge,omitempty"`
	CodeChallengeMethod string   `json:"codechallengemethod,omitempty"`
}

// AuthorizeContext is the immutable server-side context created by /authorize
// and later resumed by /issue.
type AuthorizeContext struct {
	ID string `json:"id"`
	AuthorizeRequest
	ExpiresAtUnix int64 `json:"expiresatunix"`
}

// OAuthTokenData is the frozen authorization result stored behind an auth code
// and later used to mint the final a3s access token.
type OAuthTokenData struct {
	IdentityToken *token.IdentityToken `json:"identitytoken,omitempty"`
	Audience      string               `json:"audience,omitempty"`
	Scopes        []string             `json:"scopes,omitempty"`
	ExpiresAt     time.Time            `json:"expiresat,omitempty"`
}

type authorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type openIDProviderMetadata struct {
	authorizationServerMetadata
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// Session is the unified persisted OAuth session bound to an authorization code.
type Session struct {
	Code                string          `json:"code"`
	RequestID           string          `json:"requestid"`
	RequestedAt         time.Time       `json:"requestedat"`
	Namespace           string          `json:"namespace"`
	ClientID            string          `json:"clientid"`
	RedirectURI         string          `json:"redirecturi"`
	RedirectURIIncluded bool            `json:"redirecturiincluded"`
	ScopeIncluded       bool            `json:"scopeincluded"`
	CodeChallenge       string          `json:"codechallenge,omitempty"`
	CodeChallengeMethod string          `json:"codechallengemethod,omitempty"`
	OAuthTokenData      *OAuthTokenData `json:"oauthtokendata,omitempty"`
	ExpiresAtUnix       int64           `json:"expiresatunix"`
	Invalidated         bool            `json:"invalidated"`
}

// TokenRequest is the normalized token-exchange input for the OAuth engine.
type TokenRequest struct {
	GrantType        string
	Code             string
	RedirectURI      string
	ClientID         string
	ClientSecret     string
	ClientAuthMethod api.OAuthClientTokenEndpointAuthMethodValue
	CodeVerifier     string

	// RFC 8693 token exchange parameters.
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	ActorToken         string
	ActorTokenType     string
	Audience           string
	Resource           string
}

// TokenResponse is the normalized result of a token endpoint request. It is
// serialized as-is by the token endpoint.
type TokenResponse struct {
	Token string `json:"access_token"`

	TokenType string `json:"token_type"`

	ExpiresIn int64 `json:"expires_in"`

	// IssuedTokenType is the RFC 8693 token type URI of Token. It is empty
	// for grants that do not define it, such as authorization_code.
	IssuedTokenType string `json:"issued_token_type,omitempty"`

	// Scope is the space delimited list of granted scopes. It is only set
	// when the response must advertise them, which RFC 6749 section 5.1
	// limits to the scopes differing from the ones requested.
	Scope string `json:"scope,omitempty"`
}
