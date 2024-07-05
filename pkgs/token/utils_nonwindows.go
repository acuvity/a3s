//go:build !windows

package token

import "go.acuvity.ai/bahamut"

// FromSession retrieves the token from the given bahamut.Session
// first looking at the cookie x-a3s-token, then the session.Token(.
func FromSession(session bahamut.Session) string {
	if cookie, err := session.Cookie("x-a3s-token"); err == nil {
		return cookie.Value
	}
	return session.Token()
}
