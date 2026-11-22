package oauth

import "strings"

// An Application represents the OAuth application info an identity token
// names in its claims.
type Application struct {
	ID        string `json:"ID"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// IsEmpty returns true if the claims name no OAuth application.
func (a Application) IsEmpty() bool {
	return a == Application{}
}

// ApplicationFromClaims returns the OAuth application the identity claims name.
// It is empty if they name none.
func ApplicationFromClaims(claims []string) Application {

	var app Application

	for _, c := range claims {
		switch {
		case strings.HasPrefix(c, "@oauthapp:id="):
			app.ID = strings.TrimPrefix(c, "@oauthapp:id=")
		case strings.HasPrefix(c, "@oauthapp:namespace="):
			app.Namespace = strings.TrimPrefix(c, "@oauthapp:namespace=")
		case strings.HasPrefix(c, "@oauthapp:name="):
			app.Name = strings.TrimPrefix(c, "@oauthapp:name=")
		}
	}

	return app
}
