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
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// OAuth implements the embedded OAuth authorization-code flow used by a3s.
type OAuth struct {
	store       oauthStore
	m           manipulate.Manipulator
	jwks        *token.JWKS
	issuerURL   *url.URL
	a3sIssuer   string
	a3sAudience string
	validity    time.Duration
}

type oauthStore interface {
	createAuthorizeContext(context *AuthorizeContext) error
	getAuthorizeContext(id string) (*AuthorizeContext, error)
	createOAuthSession(session *Session) error
	getOAuthSession(code string) (*Session, error)
	invalidateOAuthSession(code string) error
}

const (
	oauthGrantTypeAuthorizationCode = "authorization_code"
	oauthGrantTypeTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	oauthResponseTypeCode           = "code"
	pkceMethodS256                  = "S256"
	// OAuth state has no RFC-defined size limit. This cap is arbitrary but
	// should be sufficient for client state while bounding storage.
	maxOAuthStateLen        = 8192
	maxPKCECodeChallengeLen = 128

	// scopeOpenID is the scope that, per OIDC Core section 3.1.2.1, turns an
	// authorization request into an authentication request and so calls for
	// an ID Token in the response.
	scopeOpenID = "openid"

	// maxOAuthNonceLen bounds the nonce a3s stores and echoes. OIDC defines
	// no limit, so this mirrors the arbitrary cap applied to state.
	maxOAuthNonceLen = maxOAuthStateLen

	// RFC 8693 section 3 token type identifiers.
	oauthTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	oauthTokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"
	oauthTokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"

	tokenTypeBearer = "Bearer"
	// tokenTypeNotApplicable is the RFC 8693 section 2.2.1 token_type value
	// for an issued token that is not usable as an access token.
	tokenTypeNotApplicable = "N_A"
)

// NewOAuth returns a new OAuth engine. baseURL is the a3s issuer, and audience
// the a3s audience. Both are needed to accept native a3s tokens as the subject
// of a token exchange.
func NewOAuth(store oauthStore, manipulator manipulate.Manipulator, jwks *token.JWKS, baseURL string, audience string, validity time.Duration) (*OAuth, error) {
	issuerURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	issuerURL.Path = issuerURL.Path + "/oauth"
	issuerURL.RawPath = ""
	issuerURL.RawQuery = ""
	issuerURL.Fragment = ""
	return &OAuth{
		store:       store,
		m:           manipulator,
		jwks:        jwks,
		issuerURL:   issuerURL,
		a3sIssuer:   baseURL,
		a3sAudience: audience,
		validity:    validity,
	}, nil
}

func (o *OAuth) getClient(ctx context.Context, namespace string, clientID string) (*api.OAuthClient, error) {
	clients := &api.OAuthClientsList{}
	mctx := manipulate.NewContext(
		ctx,
		manipulate.ContextOptionNamespace(namespace),
		manipulate.ContextOptionFilter(
			elemental.NewFilterComposer().
				WithKey("clientid").Equals(clientID).
				Done(),
		),
	)

	if err := o.m.RetrieveMany(mctx, clients); err != nil {
		return nil, err
	}

	switch len(*clients) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return (*clients)[0], nil
	default:
		return nil, fmt.Errorf("more than one oauth client found")
	}
}

func (o *OAuth) getOAuthApplication(ctx context.Context, namespace string, id string) (*api.OAuthApplication, error) {
	obj := api.NewOAuthApplication()
	obj.SetIdentifier(id)

	if err := o.m.Retrieve(
		manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(namespace)),
		obj,
	); err != nil {
		if manipulate.IsObjectNotFoundError(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return obj, nil
}

func buildAuthorizeRequest(namespace string, client *api.OAuthClient, requestParams url.Values, redirectURI string) (*AuthorizeRequest, error) {
	rawScope := requestParams.Get("scope")
	requestedScopes := splitScopes(rawScope)
	state := requestParams.Get("state")
	nonce := requestParams.Get("nonce")
	codeChallenge := requestParams.Get("code_challenge")
	codeChallengeMethod := requestParams.Get("code_challenge_method")
	responseType := requestParams.Get("response_type")

	if responseType != oauthResponseTypeCode {
		return nil, newProtocolError("unsupported_response_type", "unsupported response type")
	}
	if len(state) > maxOAuthStateLen {
		return nil, newProtocolError("invalid_request", "state exceeds maximum length")
	}
	if len(nonce) > maxOAuthNonceLen {
		return nil, newProtocolError("invalid_request", "nonce exceeds maximum length")
	}
	if len(codeChallenge) > maxPKCECodeChallengeLen {
		return nil, newProtocolError("invalid_request", "code_challenge exceeds maximum length")
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
		Nonce:               nonce,
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
	expiresAt := now.Add(10 * time.Minute)
	session := &Session{
		Code:                code,
		RequestID:           authorizeContext.ID,
		RequestedAt:         now,
		Namespace:           authorizeContext.Namespace,
		ClientID:            client.ClientID,
		RedirectURI:         authorizeContext.RedirectURI,
		RedirectURIIncluded: authorizeContext.RedirectURIIncluded,
		ScopeIncluded:       authorizeContext.ScopeIncluded,
		Nonce:               authorizeContext.Nonce,
		CodeChallenge:       authorizeContext.CodeChallenge,
		CodeChallengeMethod: authorizeContext.CodeChallengeMethod,
		OAuthTokenData:      tokenData,
		ExpiresAtUnix:       expiresAt.Unix(),
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
// access token plus OAuth response metadata as TokenResponse.
func (o *OAuth) exchangeToken(ctx context.Context, namespace string, tokenRequest TokenRequest) (*TokenResponse, error) {

	var client *api.OAuthClient
	if tokenRequest.ClientID != "" {
		var err error
		if client, err = o.getClient(ctx, namespace, tokenRequest.ClientID); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, newProtocolError("invalid_client", "unknown client_id")
			}
			return nil, err
		}
		if err := validateClientAuthMethod(client, tokenRequest); err != nil {
			return nil, err
		}
		if err := validateClientSecret(client, tokenRequest); err != nil {
			return nil, err
		}
	}

	if client == nil && tokenRequest.GrantType != oauthGrantTypeTokenExchange {
		return nil, newProtocolError("invalid_client", "missing client authentication")
	}

	switch tokenRequest.GrantType {
	case oauthGrantTypeAuthorizationCode:
		return o.redeemAuthorizationCode(client, tokenRequest)
	case oauthGrantTypeTokenExchange:
		return o.exchangeSubjectToken(ctx, namespace, tokenRequest)
	default:
		return nil, newProtocolError("unsupported_grant_type", fmt.Sprintf("unsupported grant type %q", tokenRequest.GrantType))
	}
}

// redeemAuthorizationCode validates and redeems an authorization code and
// returns the final access token plus OAuth response metadata.
func (o *OAuth) redeemAuthorizationCode(client *api.OAuthClient, tokenRequest TokenRequest) (*TokenResponse, error) {

	if tokenRequest.GrantType != oauthGrantTypeAuthorizationCode {
		return nil, newProtocolError("unsupported_grant_type", fmt.Sprintf("unsupported grant type %q", tokenRequest.GrantType))
	}

	session, err := o.store.getOAuthSession(tokenRequest.Code)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, newProtocolError("invalid_grant", "authorization code not found")
		}
		return nil, err
	}
	if session.ClientID != client.ClientID {
		return nil, newProtocolError("invalid_grant", "authorization code was not issued for this client")
	}
	if err := validateTokenRedirectURI(session.RedirectURI, session.RedirectURIIncluded, tokenRequest.RedirectURI); err != nil {
		return nil, err
	}
	if err := validateCodeVerifier(session.CodeChallenge, session.CodeChallengeMethod, tokenRequest.CodeVerifier); err != nil {
		return nil, err
	}
	// The session is read first so Go can validate client binding, redirect_uri,
	// and PKCE. The store contract must still guarantee atomic single-use
	// invalidation so only one successful redemption can win after these checks.
	if err := o.store.invalidateOAuthSession(tokenRequest.Code); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, newProtocolError("invalid_grant", "authorization code not found")
		}
		if errors.Is(err, ErrAuthorizationCodeUsed) {
			return nil, newProtocolError("invalid_grant", err.Error())
		}
		return nil, err
	}

	if session.OAuthTokenData == nil {
		return nil, fmt.Errorf("oauthserver: missing oauth token data")
	}
	if !session.OAuthTokenData.ExpiresAt.IsZero() && !session.OAuthTokenData.ExpiresAt.After(time.Now().UTC()) {
		return nil, newProtocolError("invalid_grant", "authorization result expired")
	}

	// The access token lives for the default validity, unless the frozen
	// authorization result expires sooner.
	expiration := time.Now().UTC().Add(o.validity)
	if !session.OAuthTokenData.ExpiresAt.IsZero() {
		expiration = session.OAuthTokenData.ExpiresAt.UTC()
	}

	accessToken, expiresIn, err := o.signToken(
		session.Namespace,
		session.OAuthTokenData.IdentityToken,
		jwt.ClaimStrings{session.OAuthTokenData.Audience},
		expiration,
	)
	if err != nil {
		return nil, err
	}

	response := &TokenResponse{
		Token:     accessToken,
		TokenType: tokenTypeBearer,
		ExpiresIn: expiresIn,
	}

	// The openid scope makes this an authentication request, which OIDC Core
	// section 3.1.3.3 answers with an ID Token beside the access token.
	if slices.Contains(session.OAuthTokenData.Scopes, scopeOpenID) {
		idToken, _, err := o.signIDToken(
			session.Namespace,
			session.OAuthTokenData.IdentityToken,
			session.ClientID,
			session.Nonce,
			expiration,
		)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	// The client did not ask for scopes, so the granted ones may surprise
	// it and must be advertised.
	if !session.ScopeIncluded {
		response.Scope = strings.Join(session.OAuthTokenData.Scopes, " ")
	}

	return response, nil
}

// signIDToken mints an OpenID Connect ID Token, which carries flat OIDC claims
// rather than the nested a3s shape and so cannot reuse signToken.
func (o *OAuth) signIDToken(
	namespace string,
	idt *token.IdentityToken,
	audience string,
	nonce string,
	expiration time.Time,
) (string, int64, error) {

	key := o.jwks.GetLastWithPrivate()
	if key == nil {
		return "", 0, fmt.Errorf("missing signing key")
	}

	claims := jwt.MapClaims{}

	// The projection already drops every claim set below, so a source cannot
	// displace them whatever order they are written in.
	for name, value := range userinfoClaims(idt) {
		claims[name] = value
	}

	claims["iss"] = o.issuerForNamespace(namespace)
	claims["aud"] = audience
	claims["exp"] = jwt.NewNumericDate(expiration)
	claims["iat"] = jwt.NewNumericDate(time.Now().UTC())

	// OIDC Core section 3.1.3.7 makes echoing the nonce mandatory when the
	// request carried one, and relying parties reject an ID Token whose nonce
	// does not match what they sent.
	if nonce != "" {
		claims["nonce"] = nonce
	}

	// The header keeps the default JWT type. An ID Token is not an access
	// token, so the RFC 9068 at+jwt type would be wrong here.
	j := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	if key.KID != "" {
		j.Header["kid"] = key.KID
	}

	signed, err := j.SignedString(key.PrivateKey())
	if err != nil {
		return "", 0, err
	}

	return signed, int64(time.Until(expiration).Round(time.Second) / time.Second), nil
}

// exchangeSubjectToken implements the RFC 8693 token-exchange grant. It takes
// an a3s access token and mints an ID token: identity evidence signed by a3s
// for the parties named in the requested target, and nothing more.
//
// RFC 8693 section 2.1 leaves client authentication to the authorization
// server, and this grant does not require it: possession of a valid subject
// token is the authority, and everything the exchange needs is carried by that
// token.
func (o *OAuth) exchangeSubjectToken(ctx context.Context, namespace string, tokenRequest TokenRequest) (*TokenResponse, error) {

	if tokenRequest.ActorToken != "" || tokenRequest.ActorTokenType != "" {
		return nil, newProtocolError("invalid_request", "delegation through actor_token is not supported")
	}
	if tokenRequest.SubjectToken == "" {
		return nil, newProtocolError("invalid_request", "missing subject_token")
	}

	// RFC 8693 makes subject_token_type mandatory. Only the types that
	// describe an a3s token are accepted.
	switch tokenRequest.SubjectTokenType {
	case oauthTokenTypeAccessToken, oauthTokenTypeJWT:
	case "":
		return nil, newProtocolError("invalid_request", "missing subject_token_type")
	default:
		return nil, newProtocolError("invalid_request", fmt.Sprintf("unsupported subject_token_type %q", tokenRequest.SubjectTokenType))
	}

	switch tokenRequest.RequestedTokenType {
	case oauthTokenTypeIDToken, oauthTokenTypeJWT, "":
	default:
		return nil, newProtocolError("invalid_request", fmt.Sprintf("unsupported requested_token_type %q, this endpoint only issues %s", tokenRequest.RequestedTokenType, oauthTokenTypeIDToken))
	}

	if tokenRequest.Resource != "" {
		return nil, newProtocolError("invalid_target", "targeting through resource is not supported, use audience")
	}

	if tokenRequest.Audience == "" {
		return nil, newProtocolError("invalid_request", "token exchange requires audience")
	}

	// This grant issues evidence for third parties, never a token addressed
	// to a3s itself. Refusing the a3s audience keeps an exchange from
	// producing something shaped like an a3s access token.
	if tokenRequest.Audience == o.a3sAudience {
		return nil, newProtocolError("invalid_target", "the a3s audience cannot be requested")
	}
	audience := jwt.ClaimStrings{tokenRequest.Audience}

	idt, err := o.parseSubjectToken(ctx, namespace, tokenRequest.SubjectToken)
	if err != nil {
		return nil, err
	}

	// Drop the derived claims. IdentityToken.JWT re-adds them from the
	// token's own fields against the new issuer.
	identity := make([]string, 0, len(idt.Identity))
	for _, claim := range idt.Identity {
		if !strings.HasPrefix(claim, "@") {
			identity = append(identity, claim)
		}
	}
	idt.Identity = identity

	// Opaque data is carried for the bearer of the original token, not for
	// the third party this evidence is addressed to.
	idt.Opaque = nil

	// The ID token attests an authentication that already happened, so it
	// must never outlive the token that evidences it.
	idToken, expiresIn, err := o.signToken(namespace, idt, audience, idt.ExpiresAt.UTC())
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		Token: idToken,
		// The ID token cannot be used as an access token, which RFC 8693
		// section 2.2.1 spells N_A.
		TokenType:       tokenTypeNotApplicable,
		IssuedTokenType: oauthTokenTypeIDToken,
		ExpiresIn:       expiresIn,
	}, nil
}

func (o *OAuth) userinfo(namespace string, accessToken string) (map[string]any, error) {

	// The audience is left out of validation as this is an informational
	// endpoint
	idt, err := token.Parse(accessToken, o.jwks, o.issuerForNamespace(namespace), "")
	if err != nil {
		return nil, newProtocolError("invalid_token", "invalid access token")
	}

	if idt.Refresh {
		return nil, newProtocolError("invalid_token", "access token must not be a refresh token")
	}

	// Only OAuth application based tokens are supported for now.
	if idt.OAuthApplication.ID == "" {
		return nil, newProtocolError("invalid_token", "access token names no oauth application")
	}

	return userinfoClaims(idt), nil
}

func userinfoClaims(idt *token.IdentityToken) map[string]any {

	claims := map[string]any{}

	for _, claim := range idt.Identity {

		// No need for internal claims
		if strings.HasPrefix(claim, "@") {
			continue
		}

		key, value, ok := strings.Cut(claim, "=")
		if !ok || key == "" {
			continue
		}

		// No need for the upstream's own registered claims. A source copies
		// its whole claim set in, so these would read as if they were ours.
		// sub is kept: it names the subject the source authenticated.
		switch key {
		case "iss", "aud", "exp", "nbf", "iat", "jti", "nonce",
			"azp", "at_hash", "c_hash", "sid", "auth_time":
			continue
		}

		// add multi-value claims as arrays
		switch existing := claims[key].(type) {
		case nil:
			claims[key] = value
		case string:
			claims[key] = []string{existing, value}
		case []string:
			claims[key] = append(existing, value)
		}
	}

	return claims
}

// parseSubjectToken validates an exchange subject token. Both tokens minted by
// this namespace's authorization-code flow and native a3s tokens are accepted.
func (o *OAuth) parseSubjectToken(ctx context.Context, namespace string, subjectToken string) (*token.IdentityToken, error) {

	unverified, err := token.ParseUnverified(subjectToken)
	if err != nil {
		return nil, newProtocolError("invalid_request", fmt.Sprintf("unable to parse subject_token: %s", err))
	}

	var idt *token.IdentityToken

	switch unverified.Issuer {

	case o.issuerForNamespace(namespace):
		// The audience is left out here so the token can be checked against
		// the application it names, which is only trustworthy once the
		// signature has been verified.
		if idt, err = token.Parse(subjectToken, o.jwks, unverified.Issuer, ""); err != nil {
			return nil, newProtocolError("invalid_request", fmt.Sprintf("invalid subject_token: %s", err))
		}
		if err := o.validateSubjectTokenApplication(ctx, idt); err != nil {
			return nil, err
		}

	case o.a3sIssuer:
		if idt, err = token.Parse(subjectToken, o.jwks, unverified.Issuer, o.a3sAudience); err != nil {
			return nil, newProtocolError("invalid_request", fmt.Sprintf("invalid subject_token: %s", err))
		}

	default:
		return nil, newProtocolError("invalid_request", fmt.Sprintf("subject_token issuer %q is not this authorization server", unverified.Issuer))
	}

	if idt.Refresh {
		return nil, newProtocolError("invalid_request", "subject_token must not be a refresh token")
	}
	// The issued token is capped to the subject token's expiration, so the
	// subject token must carry one.
	if idt.ExpiresAt == nil || idt.ExpiresAt.IsZero() {
		return nil, newProtocolError("invalid_request", "subject_token has no expiration")
	}

	return idt, nil
}

func (o *OAuth) validateSubjectTokenApplication(ctx context.Context, idt *token.IdentityToken) error {

	if idt.OAuthApplication.ID == "" {
		return newProtocolError("invalid_request", "subject_token names no oauth application")
	}

	app, err := o.getOAuthApplication(ctx, idt.OAuthApplication.Namespace, idt.OAuthApplication.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return newProtocolError("invalid_request", "subject_token names an unknown oauth application")
		}
		return err
	}
	if app.Disabled {
		return newProtocolError("invalid_request", ErrOAuthApplicationDisabled.Error())
	}

	// Only a token still addressed to its own application can be exchanged.
	// A token whose audience was already retargeted by an earlier exchange is
	// evidence held for a third party rather than an a3s access token, and
	// must not be exchanged again.
	if !slices.Contains(idt.Audience, app.Audience) {
		return newProtocolError("invalid_request", "subject_token was not issued for its oauth application")
	}

	return nil
}

// signToken signs idt as a token issued by namespace and returns it alongside
// its lifetime in seconds. It is the single signing path of every token this
// authorization server issues.
func (o *OAuth) signToken(namespace string, idt *token.IdentityToken, audience jwt.ClaimStrings, expiration time.Time) (string, int64, error) {
	key := o.jwks.GetLastWithPrivate()
	if key == nil {
		return "", 0, fmt.Errorf("missing signing key")
	}

	signed, err := idt.JWT(
		key.PrivateKey(),
		key.KID,
		o.issuerForNamespace(namespace),
		audience,
		expiration,
		nil,
	)
	if err != nil {
		return "", 0, err
	}

	return signed, int64(time.Until(expiration).Round(time.Second) / time.Second), nil
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
	authorizeContext, err := o.store.getAuthorizeContext(authorizeRequestID)
	if err == nil {
		if authorizeContext.ExpiresAtUnix <= time.Now().Unix() {
			err = ErrAuthorizeContextExpired
		} else {
			oauthClient, clientErr := o.getClient(ctx, authorizeContext.Namespace, authorizeContext.ClientID)
			if clientErr != nil {
				err = clientErr
			} else {
				oauthApplication, appErr := o.getOAuthApplication(ctx, oauthClient.Namespace, oauthClient.OauthApplicationID)
				if appErr != nil {
					err = appErr
				} else if oauthApplication.Disabled {
					err = ErrOAuthApplicationDisabled
				} else {
					return authorizeContext, oauthClient, oauthApplication, nil
				}
			}
		}
	}

	switch {
	case errors.Is(err, ErrOAuthApplicationDisabled):
		return nil, nil, nil, elemental.NewError(
			"Forbidden",
			err.Error(),
			"a3s:authn",
			http.StatusForbidden,
		)
	case errors.Is(err, ErrAuthorizeContextExpired):
		return nil, nil, nil, elemental.NewError(
			"Bad Request",
			err.Error(),
			"a3s:authn",
			http.StatusBadRequest,
		)
	case errors.Is(err, ErrNotFound):
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
	case api.OAuthClientTokenEndpointAuthMethodClientSecretAny:
		// no transport requirement: either client_secret_basic or client_secret_post is accepted.
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
	case api.OAuthClientTokenEndpointAuthMethodClientSecretBasic, api.OAuthClientTokenEndpointAuthMethodClientSecretPost, api.OAuthClientTokenEndpointAuthMethodClientSecretAny:
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
	if sessionRedirectURI == "" {
		return newProtocolError("invalid_grant", "authorization code missing redirect_uri")
	}
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
		registered.RawQuery == requested.RawQuery &&
		registered.Fragment == requested.Fragment
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
