package oauth2provider

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type googleEmailResp struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Verified bool   `json:"email_verified"`
}

type google struct {
	authURL  string
	tokenURL string
}

// NewGoogleProvider returns a new Google backed Provider.
// The claims will contain the login and the email of the user that is
// both primary and verified.
func NewGoogleProvider() Provider {
	return &google{
		authURL:  "https://accounts.google.com/o/oauth2/auth",
		tokenURL: "https://accounts.google.com/o/oauth2/token",
	}
}

func (g *google) AuthURL() string {
	return g.authURL
}

func (g *google) TokenURL() string {
	return g.tokenURL
}

func (*google) RetrieveClaims(client *http.Client) ([]string, error) {

	claims := []string{
		"provider=google",
	}

	// Get login
	r, err := http.NewRequest(http.MethodGet, "https://accounts.google.com/o/oauth2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("google: unable to retrieve user data: %s", err)
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("google: unable to send request to retrieve user data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google: unable to send request to retrieve user data: %s", resp.Status)
	}

	l := googleEmailResp{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("google: unable to decode oauth user data: %w", err)
	}

	if !l.Verified {
		return nil, fmt.Errorf("google: email is not verified")
	}

	if l.Email != "" {
		claims = append(claims, "email="+l.Email)
	} else {
		return nil, fmt.Errorf("google: missing email information")
	}

	if l.Name != "" {
		claims = append(claims, "login="+l.Name)
	} else {
		return nil, fmt.Errorf("google: missing name information")
	}

	return claims, nil
}
