package oauth2provider

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type hgEmailResp struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Verified bool   `json:"email_verified"`
}

type huggingface struct {
	authURL  string
	tokenURL string
}

// NewHuggingfaceProvider returns a new Huggingface backed Provider.
// The claims will contain the login and the email of the user that is
// both primary and verified.
func NewHuggingfaceProvider() Provider {
	return &huggingface{
		authURL:  "https://huggingface.co/oauth/authorize",
		tokenURL: "https://huggingface.co/oauth/token",
	}
}

func (g *huggingface) AuthURL() string {
	return g.authURL
}

func (g *huggingface) TokenURL() string {
	return g.tokenURL
}

func (*huggingface) RetrieveClaims(client *http.Client) ([]string, error) {

	claims := []string{
		"provider=huggingface",
	}

	// Get login
	r, err := http.NewRequest(http.MethodGet, "https://huggingface.co/oauth/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("huggingface: unable to retrieve user data: %s", err)
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("huggingface: unable to send request to retrieve user data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("huggingface: unable to send request to retrieve user data: %s", resp.Status)
	}

	l := hgEmailResp{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("huggingface: unable to decode oauth user data: %w", err)
	}

	if !l.Verified {
		return nil, fmt.Errorf("huggingface: email is not verified")
	}

	if l.Email != "" {
		claims = append(claims, "email="+l.Email)
		if domain := getDomain(l.Email); domain != "" {
			claims = append(claims, "domain="+domain)
		}
	} else {
		return nil, fmt.Errorf("huggingface: missing email information")
	}

	if l.Name != "" {
		claims = append(claims, "login="+l.Name)
	} else {
		return nil, fmt.Errorf("huggingface: missing name information")
	}

	return claims, nil
}
