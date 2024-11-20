package oauth2provider

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type gitlabUserResp struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

type gitlabEmailResp struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	ConfirmedAt string `json:"confirmed_at"`
}

type gitlab struct {
	authURL  string
	tokenURL string
}

// NewGitlabProvider returns a new Gitlab backed Provider.
// The claims will contain the login and the email of the user that is
// both primary and verified.
func NewGitlabProvider() Provider {
	return &gitlab{
		authURL:  "https://gitlab.com/oauth/authorize",
		tokenURL: "https://gitlab.com/oauth/token",
	}
}

func (g *gitlab) AuthURL() string {
	return g.authURL
}

func (g *gitlab) TokenURL() string {
	return g.tokenURL
}

func (*gitlab) RetrieveClaims(client *http.Client) ([]string, error) {

	claims := []string{
		"provider=gitlab",
	}

	// Get login
	r, err := http.NewRequest(http.MethodGet, "https://gitlab.com/oauth/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("gitlab: unable to retrieve user data: %s", err)
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("gitlab: unable to send request to retrieve user data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitlab: unable to send request to retrieve user data: %s", resp.Status)
	}

	l := gitlabUserResp{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("gitlab: unable to decode oauth user data: %w", err)
	}

	if !l.Verified {
		return nil, fmt.Errorf("gitlab: primary email is not verified")
	}

	if l.Email == "" {
		return nil, fmt.Errorf("gitlab: missing primary email")
	}

	claims = append(claims, "email="+l.Email)
	if domain := getDomain(l.Email); domain != "" {
		claims = append(claims, "domain="+domain)
	}

	if l.Name != "" {
		claims = append(claims, "login="+l.Name)
	} else {
		return nil, fmt.Errorf("gitlab: missing name information")
	}

	// Get emails
	r, err = http.NewRequest(http.MethodGet, "https://gitlab.com/api/v4/user/emails", nil)
	if err != nil {
		return nil, fmt.Errorf("gitlab: unable to retrieve user emails: %s", err)
	}

	resp, err = client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("gitlab: unable to send request to retrieve user emails: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitlab: unable to send request to retrieve user emails: %s", resp.Status)
	}

	emails := []gitlabEmailResp{}
	dec = json.NewDecoder(resp.Body)
	if err := dec.Decode(&emails); err != nil {
		return nil, fmt.Errorf("gitlab: unable to decode oauth user emails: %w", err)
	}

	for _, email := range emails {

		if email.ConfirmedAt == "" || email.Email == l.Email {
			continue
		}

		claims = append(claims, "alt_email="+email.Email)
		if domain := getDomain(email.Email); domain != "" {
			claims = append(claims, "domain="+domain)
		}
	}

	return claims, nil
}
