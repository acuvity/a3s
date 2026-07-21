package google

import "github.com/golang-jwt/jwt/v5"

// AccessToken represents the token returned by the Google OAuth2 token endpoint
// when exchanging a service account assertion.
type AccessToken struct {
	AccessToken string `json:"access_token"`
}

// assertionClaims are the claims of the service account JWT assertion sent to
// the Google OAuth2 token endpoint. In addition to the standard registered
// claims, Google requires the requested `scope` to be part of the assertion.
type assertionClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// User represents a Google Workspace Directory API user.
type User struct {
	ID           string `json:"id"`
	PrimaryEmail string `json:"primaryEmail"`
	Suspended    bool   `json:"suspended"`
	Name         struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
		FullName   string `json:"fullName"`
	} `json:"name"`
}

// Membership represents a Google Workspace Directory API group the user belongs to.
type Membership struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// groupsResponse is a single page of the Directory API groups.list response.
type groupsResponse struct {
	Groups        []Membership `json:"groups"`
	NextPageToken string       `json:"nextPageToken"`
}
