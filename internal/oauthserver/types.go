package oauthserver

import (
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
)

// AuthorizeRequest contains normalized authorization request data after
// validation.
type AuthorizeRequest struct {
	Namespace           string   `bson:"namespace"`
	ClientID            string   `bson:"clientid"`
	RedirectURI         string   `bson:"redirecturi"`
	RedirectURIIncluded bool     `bson:"redirecturiincluded"`
	ScopeIncluded       bool     `bson:"scopeincluded"`
	RequestedScopes     []string `bson:"requestedscopes,omitempty"`
	State               string   `bson:"state,omitempty"`
	CodeChallenge       string   `bson:"codechallenge,omitempty"`
	CodeChallengeMethod string   `bson:"codechallengemethod,omitempty"`
}

// AuthorizeContext is the immutable server-side context created by /authorize
// and later resumed by /issue.
type AuthorizeContext struct {
	ID                        string `bson:"id"`
	AuthorizeRequest          `bson:",inline"`
	OAuthApplicationID        string    `bson:"oauthapplicationid"`
	OAuthApplicationNamespace string    `bson:"oauthapplicationnamespace"`
	ExpiresAt                 time.Time `bson:"expiresat"`
}

// OAuthTokenData is the frozen authorization result stored behind an auth code
// and later used to mint the final a3s access token.
type OAuthTokenData struct {
	IdentityToken *token.IdentityToken `bson:"identitytoken,omitempty"`
	Audience      string               `bson:"audience,omitempty"`
	Scopes        []string             `bson:"scopes,omitempty"`
	ExpiresAt     time.Time            `bson:"expiresat,omitempty"`
}

// Session is the unified persisted OAuth session bound to an authorization code.
type Session struct {
	Code                string          `bson:"code"`
	RequestID           string          `bson:"requestid"`
	RequestedAt         time.Time       `bson:"requestedat"`
	Namespace           string          `bson:"namespace"`
	ClientID            string          `bson:"clientid"`
	RedirectURI         string          `bson:"redirecturi"`
	RedirectURIIncluded bool            `bson:"redirecturiincluded"`
	ScopeIncluded       bool            `bson:"scopeincluded"`
	CodeChallenge       string          `bson:"codechallenge,omitempty"`
	CodeChallengeMethod string          `bson:"codechallengemethod,omitempty"`
	OAuthTokenData      *OAuthTokenData `bson:"oauthtokendata,omitempty"`
	ExpiresAt           time.Time       `bson:"expiresat"`
	Invalidated         bool            `bson:"invalidated"`
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
}
