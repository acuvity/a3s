package oauth2provider

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type googleEmailResp struct {
	Email     string `json:"email"`
	HD        string `json:"hd"`
	Verified  bool   `json:"email_verified"`
	AvatarURL string `json:"picture"`
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
	r, err := http.NewRequest(http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("google: unable to retrieve user data: %w", err)
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("google: unable to send request to retrieve user data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google: unable to send request to retrieve user data: %s", resp.Status)
	}

	l := googleEmailResp{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("google: unable to decode oauth user data: %w", err)
	}

	if l.AvatarURL != "" {
		claims = append(claims, "avatar="+l.AvatarURL)
	}

	if !l.Verified {
		return nil, fmt.Errorf("google: email is not verified")
	}

	if l.Email != "" {
		claims = append(claims, "email="+l.Email)
		if domain := getDomain(l.Email); domain != "" {
			claims = append(claims, "domain="+domain)
		}
	} else {
		return nil, fmt.Errorf("google: missing email information")
	}

	if l.HD != "" {
		claims = append(claims, "hd="+l.HD)
	}

	return claims, nil
}
