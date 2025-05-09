package oauth2provider

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type githubLoginResp struct {
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmailResp struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type github struct {
	authURL  string
	tokenURL string
}

// NewGithubProvider returns a new Github backed Provider.
// The claims will contain the login and the email of the user that is
// both primary and verified.
func NewGithubProvider() Provider {
	return &github{
		authURL:  "https://github.com/login/oauth/authorize",
		tokenURL: "https://github.com/login/oauth/access_token",
	}
}

func (g *github) AuthURL() string {
	return g.authURL
}

func (g *github) TokenURL() string {
	return g.tokenURL
}

func (*github) RetrieveClaims(client *http.Client) ([]string, error) {

	claims := []string{
		"provider=github",
	}

	// Get login
	r, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("github: unable to retrieve user data: %w", err)
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("github: unable to send request to retrieve user data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: unable to send request to retrieve user data: %s", resp.Status)
	}

	l := githubLoginResp{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("github: unable to decode oauth user data: %w", err)
	}

	if l.Login != "" {
		claims = append(claims, "login="+l.Login)
	} else {
		return nil, fmt.Errorf("github: missing login information")
	}

	if l.AvatarURL != "" {
		claims = append(claims, "avatar="+l.AvatarURL)
	}

	// Get emails
	r, err = http.NewRequest(http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, fmt.Errorf("github: unable to retrieve user emails: %w", err)
	}

	resp, err = client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("github: unable to send request to retrieve user emails: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: unable to send request to retrieve user emails: %s", resp.Status)
	}

	emails := []githubEmailResp{}
	dec = json.NewDecoder(resp.Body)
	if err := dec.Decode(&emails); err != nil {
		return nil, fmt.Errorf("github: unable to decode oauth user emails: %w", err)
	}

	for _, email := range emails {

		if !email.Verified {
			continue
		}

		if email.Primary {
			claims = append(claims, "email="+email.Email)
		} else {
			claims = append(claims, "email:alt="+email.Email)
		}

		if domain := getDomain(email.Email); domain != "" {
			claims = append(claims, "domain="+domain)
		}
	}

	return claims, nil
}
