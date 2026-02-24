package dsgauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultTimeout = 30 * time.Second
	defaultLeeway  = 60 * time.Second
)

// Validator validates access tokens against DSG auth infrastructure.
type Validator interface {
	ValidateAccessToken(ctx context.Context, token string) (map[string]any, error)
}

// Config contains DSG auth connectivity settings.
type Config struct {
	URL          string
	ClientID     string
	ClientSecret string
	Timeout      time.Duration
	Leeway       time.Duration
}

// Client validates tokens using DSG auth APIs.
type Client struct {
	url          string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	leeway       time.Duration

	mu        sync.Mutex
	apiToken  string
	apiTokenE time.Time
}

// NewClient returns a DSG validator client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("dsg auth url is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("dsg auth client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("dsg auth client secret is required")
	}

	base := strings.TrimRight(cfg.URL, "/")
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("invalid dsg auth url: %w", err)
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = defaultLeeway
	}

	return &Client{
		url:          base,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		httpClient:   &http.Client{Timeout: cfg.Timeout},
		leeway:       cfg.Leeway,
	}, nil
}

// ValidateAccessToken verifies the access token using DSG auth public keys.
func (c *Client) ValidateAccessToken(ctx context.Context, token string) (map[string]any, error) {
	claims, err := peekJWT(token)
	if err != nil {
		return nil, fmt.Errorf("unable to inspect token: %w", err)
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return nil, fmt.Errorf("missing issuer claim")
	}

	publicKey, err := c.publicKey(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve signing key: %w", err)
	}

	verified, err := verifyJWT(token, publicKey, c.leeway)
	if err != nil {
		return nil, fmt.Errorf("unable to validate token: %w", err)
	}

	out := make(map[string]any, len(verified))
	for k, v := range verified {
		out[k] = v
	}

	jti, _ := out["jti"].(string)
	if jti != "" {
		tokenInfo, err := c.tokenInfo(ctx, jti)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve token info: %w", err)
		}

		for k, v := range tokenInfo {
			if strings.HasPrefix(k, "_") {
				continue
			}
			out[k] = v
		}
	}

	return out, nil
}

func (c *Client) publicKey(ctx context.Context, issuer string) (string, error) {
	token, err := c.loginToken(ctx)
	if err != nil {
		return "", err
	}

	u := c.url + "/v2/apis/auth/internal/oauth/token-keys?iss=" + url.QueryEscape(issuer)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}

	var body struct {
		Data []struct {
			Key struct {
				Public struct {
					Data string `json:"data"`
				} `json:"public"`
			} `json:"key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if len(body.Data) == 0 {
		return "", fmt.Errorf("empty signing key response")
	}
	if body.Data[0].Key.Public.Data == "" {
		return "", fmt.Errorf("missing public key in response")
	}

	return body.Data[0].Key.Public.Data, nil
}

func (c *Client) tokenInfo(ctx context.Context, jti string) (map[string]any, error) {
	token, err := c.loginToken(ctx)
	if err != nil {
		return nil, err
	}

	u := c.url + "/v2/apis/auth/tokens/" + url.PathEscape(jti)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	return body, nil
}

func (c *Client) loginToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.apiToken != "" && time.Now().Before(c.apiTokenE) {
		t := c.apiToken
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("scope", "*")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v2/apis/auth/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("missing access_token in login response")
	}

	expiresIn := time.Duration(body.ExpiresIn * float64(time.Second))
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}

	c.mu.Lock()
	c.apiToken = body.AccessToken
	c.apiTokenE = time.Now().Add(time.Duration(float64(expiresIn) * 0.8))
	t := c.apiToken
	c.mu.Unlock()

	return t, nil
}

func peekJWT(tokenString string) (jwt.MapClaims, error) {
	token, _, err := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
		jwt.WithJSONNumber(),
	).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	return claims, nil
}

func verifyJWT(tokenString string, publicKeyPEM string, leeway time.Duration) (jwt.MapClaims, error) {
	pubKey, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(leeway),
		jwt.WithJSONNumber(),
	)

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	return claims, nil
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Support PKCS#1 RSA public keys.
	if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaPub, nil
	}

	// Support PKIX SubjectPublicKeyInfo public keys.
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return rsaPub, nil
}
