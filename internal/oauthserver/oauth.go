package oauthserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/globalsign/mgo"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// OAuth implements the embedded OAuth authorization-code flow used by a3s.
type OAuth struct {
	store     *store
	jwks      *token.JWKS
	issuerURL *url.URL
	validity  time.Duration
}

const (
	oauthGrantTypeAuthorizationCode = "authorization_code"
	oauthResponseTypeCode           = "code"
	pkceMethodS256                  = "S256"
)

// NewOAuth returns a new OAuth engine.
func NewOAuth(manipulator manipulate.Manipulator, jwks *token.JWKS, baseURL *url.URL, validity time.Duration) *OAuth {
	issuerURL := *baseURL
	issuerURL.Path = issuerURL.Path + "/oauth"
	issuerURL.RawPath = ""
	issuerURL.RawQuery = ""
	issuerURL.Fragment = ""
	return &OAuth{
		store:     newStore(manipulator),
		jwks:      jwks,
		issuerURL: &issuerURL,
		validity:  validity,
	}
}

func buildAuthorizeRequest(namespace string, client *api.OAuthClient, requestParams url.Values, redirectURI string) (*AuthorizeRequest, error) {
	rawScope := requestParams.Get("scope")
	requestedScopes := splitScopes(rawScope)
	state := requestParams.Get("state")
	codeChallenge := requestParams.Get("code_challenge")
	codeChallengeMethod := requestParams.Get("code_challenge_method")
	responseType := requestParams.Get("response_type")

	if responseType != oauthResponseTypeCode {
		return nil, newProtocolError("unsupported_response_type", "unsupported response type")
	}
	if codeChallenge != "" && codeChallengeMethod != pkceMethodS256 {
		return nil, newProtocolError("invalid_request", "unsupported code challenge method")
	}
	if client.TokenEndpointAuthMethod == api.OAuthClientTokenEndpointAuthMethodNone && codeChallenge == "" {
		return nil, newProtocolError("invalid_request", "PKCE is required")
	}
	if len(requestedScopes) > 0 && !containsAll(client.Scopes, requestedScopes) {
		return nil, newProtocolError("invalid_scope", "invalid scope")
	}

	return &AuthorizeRequest{
		Namespace:           namespace,
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		RedirectURIIncluded: requestParams.Get("redirect_uri") != "",
		ScopeIncluded:       strings.TrimSpace(rawScope) != "",
		RequestedScopes:     append([]string{}, requestedScopes...),
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}, nil
}

// issueAuthorizationCode materializes an authorization code from a previously
// authenticated and finalized authorization result.
func (o *OAuth) issueAuthorizationCode(client *api.OAuthClient, authorizeContext *AuthorizeContext, tokenData *OAuthTokenData) (string, error) {
	code, err := generateAuthorizationCode()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	session := &Session{
		Code:                code,
		RequestID:           authorizeContext.ID,
		RequestedAt:         now,
		Namespace:           authorizeContext.Namespace,
		ClientID:            client.ClientID,
		RedirectURI:         authorizeContext.RedirectURI,
		RedirectURIIncluded: authorizeContext.RedirectURIIncluded,
		ScopeIncluded:       authorizeContext.ScopeIncluded,
		CodeChallenge:       authorizeContext.CodeChallenge,
		CodeChallengeMethod: authorizeContext.CodeChallengeMethod,
		OAuthTokenData:      tokenData,
		ExpiresAt:           now.Add(10 * time.Minute),
	}

	if err := o.store.createOAuthSession(session); err != nil {
		return "", err
	}

	return code, nil
}

// CompleteAuthorize mints an authorization code for a completed authorize
// flow and returns the final redirect URL to the OAuth client.
func (o *OAuth) CompleteAuthorize(
	idt *token.IdentityToken,
	authorizeContext *AuthorizeContext,
	oauthClient *api.OAuthClient,
	oauthApplication *api.OAuthApplication,
) (string, error) {
	var expiresAt time.Time
	if idt.ExpiresAt != nil {
		expiresAt = idt.ExpiresAt.Time
	}

	code, err := o.issueAuthorizationCode(
		oauthClient,
		authorizeContext,
		&OAuthTokenData{
			IdentityToken: idt,
			Audience:      oauthApplication.Audience,
			Scopes:        append([]string{}, authorizeContext.RequestedScopes...),
			ExpiresAt:     expiresAt,
		},
	)
	if err != nil {
		return "", err
	}

	redirectURI, _ := url.Parse(authorizeContext.RedirectURI)

	query := redirectURI.Query()
	query.Set("code", code)
	if authorizeContext.State != "" {
		query.Set("state", authorizeContext.State)
	}
	redirectURI.RawQuery = query.Encode()

	return redirectURI.String(), nil
}

// exchangeToken validates and redeems a token request and returns the final
// access token plus OAuth response metadata.
func (o *OAuth) exchangeToken(client *api.OAuthClient, tokenRequest TokenRequest) (string, int64, []string, bool, error) {
	if err := validateClientAuthMethod(client, tokenRequest); err != nil {
		return "", 0, nil, false, err
	}
	if err := validateClientSecret(client, tokenRequest); err != nil {
		return "", 0, nil, false, err
	}
	if tokenRequest.GrantType != oauthGrantTypeAuthorizationCode {
		return "", 0, nil, false, newProtocolError("unsupported_grant_type", fmt.Sprintf("unsupported grant type %q", tokenRequest.GrantType))
	}

	session, err := o.store.getOAuthSession(tokenRequest.Code)
	if err != nil {
		return "", 0, nil, false, err
	}
	if session.ClientID != client.ClientID {
		return "", 0, nil, false, newProtocolError("invalid_grant", "authorization code was not issued for this client")
	}
	if err := validateTokenRedirectURI(session.RedirectURI, session.RedirectURIIncluded, tokenRequest.RedirectURI); err != nil {
		return "", 0, nil, false, err
	}
	if err := validateCodeVerifier(session.CodeChallenge, session.CodeChallengeMethod, tokenRequest.CodeVerifier); err != nil {
		return "", 0, nil, false, err
	}
	if err := o.store.invalidateOAuthSession(tokenRequest.Code); err != nil {
		if errors.Is(err, ErrAuthorizationCodeUsed) {
			return "", 0, nil, false, newProtocolError("invalid_grant", err.Error())
		}
		return "", 0, nil, false, err
	}

	if session.OAuthTokenData == nil {
		return "", 0, nil, false, fmt.Errorf("oauthserver: missing oauth token data")
	}
	if !session.OAuthTokenData.ExpiresAt.IsZero() && !session.OAuthTokenData.ExpiresAt.After(time.Now().UTC()) {
		return "", 0, nil, false, newProtocolError("invalid_grant", "authorization result expired")
	}

	accessToken, expiresIn, err := o.mintAccessToken(session.Namespace, session.OAuthTokenData)
	if err != nil {
		return "", 0, nil, false, err
	}

	return accessToken, expiresIn, append([]string{}, session.OAuthTokenData.Scopes...), !session.ScopeIncluded, nil
}

func (o *OAuth) mintAccessToken(namespace string, data *OAuthTokenData) (string, int64, error) {
	if data == nil || data.IdentityToken == nil {
		return "", 0, fmt.Errorf("missing token exchange result")
	}

	expiration := time.Now().UTC().Add(o.validity)
	if !data.ExpiresAt.IsZero() {
		expiration = data.ExpiresAt.UTC()
	}
	key := o.jwks.GetLastWithPrivate()
	if key == nil {
		return "", 0, fmt.Errorf("missing signing key")
	}

	issuer := o.issuerForNamespace(namespace)

	accessToken, err := data.IdentityToken.JWT(
		key.PrivateKey(),
		key.KID,
		issuer,
		jwt.ClaimStrings{data.Audience},
		expiration,
		nil,
	)
	if err != nil {
		return "", 0, err
	}

	return accessToken, int64(time.Until(expiration).Round(time.Second) / time.Second), nil
}

// issuerForNamespace returns the OAuth issuer identifier for the provided namespace.
func (o *OAuth) issuerForNamespace(namespace string) string {
	if namespace == "/" {
		return o.issuerURL.String()
	}

	encodedNamespace := encodeNamespace(namespace)

	return o.issuerURL.String() + "/" + encodedNamespace
}

// LoadAuthorizeContext resolves an authorize request together with its client
// registration and oauth application.
func (o *OAuth) LoadAuthorizeContext(ctx context.Context, authorizeRequestID string) (*AuthorizeContext, *api.OAuthClient, *api.OAuthApplication, error) {
	authorizeContext, oauthClient, oauthApplication, err := o.store.loadAuthorizeContext(ctx, authorizeRequestID)
	if err == nil {
		return authorizeContext, oauthClient, oauthApplication, nil
	}

	switch {
	case errors.Is(err, ErrOAuthApplicationDisabled):
		return nil, nil, nil, elemental.NewError(
			"Forbidden",
			err.Error(),
			"a3s:authn",
			http.StatusForbidden,
		)
	case errors.Is(err, ErrAuthorizeContextExpired), errors.Is(err, ErrAuthorizeContextMismatch):
		return nil, nil, nil, elemental.NewError(
			"Bad Request",
			err.Error(),
			"a3s:authn",
			http.StatusBadRequest,
		)
	case errors.Is(err, mgo.ErrNotFound):
		return nil, nil, nil, elemental.NewError(
			"Not Found",
			"unknown authorize request",
			"a3s:authn",
			http.StatusNotFound,
		)
	default:
		return nil, nil, nil, elemental.NewError(
			"Internal Server Error",
			"unable to load authorize request",
			"a3s:authn",
			http.StatusInternalServerError,
		)
	}
}

func validateClientAuthMethod(client *api.OAuthClient, tokenRequest TokenRequest) error {
	switch client.TokenEndpointAuthMethod {
	case api.OAuthClientTokenEndpointAuthMethodClientSecretBasic:
		if tokenRequest.ClientAuthMethod != api.OAuthClientTokenEndpointAuthMethodClientSecretBasic {
			return newProtocolError("invalid_client", "client requires client_secret_basic")
		}
	case api.OAuthClientTokenEndpointAuthMethodClientSecretPost:
		if tokenRequest.ClientAuthMethod != api.OAuthClientTokenEndpointAuthMethodClientSecretPost {
			return newProtocolError("invalid_client", "client requires client_secret_post")
		}
	case api.OAuthClientTokenEndpointAuthMethodNone:
		if tokenRequest.ClientAuthMethod != api.OAuthClientTokenEndpointAuthMethodNone {
			return newProtocolError("invalid_client", "client does not allow secret-based authentication")
		}
	default:
		return fmt.Errorf("oauthserver: unsupported token endpoint auth method %q", client.TokenEndpointAuthMethod)
	}

	return nil
}

func validateClientSecret(client *api.OAuthClient, tokenRequest TokenRequest) error {
	switch client.TokenEndpointAuthMethod {
	case api.OAuthClientTokenEndpointAuthMethodNone:
		return nil
	case api.OAuthClientTokenEndpointAuthMethodClientSecretBasic, api.OAuthClientTokenEndpointAuthMethodClientSecretPost:
		if client.ClientSecret == "" {
			return newProtocolError("invalid_client", fmt.Sprintf("confidential client %q has no client secret", client.ClientID))
		}
		if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(tokenRequest.ClientSecret)) != 1 {
			return newProtocolError("invalid_client", "invalid client secret")
		}
		return nil
	default:
		return fmt.Errorf("oauthserver: unsupported token endpoint auth method %q", client.TokenEndpointAuthMethod)
	}
}

func splitScopes(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

func validateTokenRedirectURI(sessionRedirectURI string, redirectURIIncluded bool, tokenRedirectURI string) error {
	if redirectURIIncluded && tokenRedirectURI == "" {
		return newProtocolError("invalid_grant", "missing redirect_uri")
	}

	if tokenRedirectURI != "" && sessionRedirectURI != tokenRedirectURI {
		return newProtocolError("invalid_grant", "redirect_uri does not match authorization code")
	}

	return nil
}

func validateAuthorizeRedirectURI(client *api.OAuthClient, redirectURI string) (string, error) {
	if redirectURI == "" {
		if len(client.RedirectURIs) == 1 {
			return client.RedirectURIs[0], nil
		}
		return "", newProtocolError("invalid_request", "invalid redirect uri")
	}

	if redirectURIMatches(redirectURI, client.RedirectURIs) {
		return redirectURI, nil
	}

	return "", newProtocolError("invalid_request", "invalid redirect uri")
}

func redirectURIMatches(requestedURI string, registeredURIs []string) bool {
	requested, err := url.Parse(requestedURI)
	if err != nil {
		return false
	}

	requestedIsLoopback := isRFC8252LoopbackCandidate(requested)

	for _, registeredURI := range registeredURIs {
		if registeredURI == requestedURI {
			return true
		}
		if requestedIsLoopback && redirectURIMatchesLoopback(requested, registeredURI) {
			return true
		}
	}

	return false
}

func redirectURIMatchesLoopback(requested *url.URL, registeredURI string) bool {
	registered, err := url.Parse(registeredURI)
	if err != nil {
		return false
	}

	// RFC 8252 section 7.3 requires authorization servers to accept any port
	// for loopback redirect URIs chosen dynamically by native apps at runtime.
	// If the registered URI explicitly includes a port, require an exact match.
	return registered.Scheme == "http" &&
		registered.Hostname() == requested.Hostname() &&
		(registered.Port() == "" || registered.Port() == requested.Port()) &&
		registered.Path == requested.Path &&
		registered.RawQuery == requested.RawQuery
}

func isRFC8252LoopbackCandidate(u *url.URL) bool {
	return u.Scheme == "http" && isLoopbackIP(u.Hostname())
}

func validateCodeVerifier(codeChallenge string, codeChallengeMethod string, codeVerifier string) error {
	if codeChallenge == "" {
		if codeVerifier == "" {
			return nil
		}
		return newProtocolError("invalid_grant", "unexpected code verifier")
	}
	if codeVerifier == "" {
		return newProtocolError("invalid_grant", "missing code verifier")
	}
	if !isValidCodeVerifier(codeVerifier) {
		return newProtocolError("invalid_grant", "invalid code verifier")
	}

	switch codeChallengeMethod {
	case pkceMethodS256:
		sum := sha256.Sum256([]byte(codeVerifier))
		if subtle.ConstantTimeCompare(
			[]byte(base64.RawURLEncoding.EncodeToString(sum[:])),
			[]byte(codeChallenge),
		) == 1 {
			return nil
		}
	}

	return newProtocolError("invalid_grant", "invalid code challenge")
}

func isValidCodeVerifier(codeVerifier string) bool {
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return false
	}

	for _, char := range codeVerifier {
		switch {
		case char >= 'A' && char <= 'Z':
		case char >= 'a' && char <= 'z':
		case char >= '0' && char <= '9':
		case char == '-' || char == '.' || char == '_' || char == '~':
		default:
			return false
		}
	}

	return true
}

func generateAuthorizationCode() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauthserver: generate authorization code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
