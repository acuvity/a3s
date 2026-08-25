package oauthserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-zoo/bone"
	"github.com/gofrs/uuid"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/bahamut"
)

const (
	encodedNamespacePathParam = "namespace"
	routeAuthorizeRoot        = "/oauth/authorize"
	routeTokenRoot            = "/oauth/token"
	routeUserinfoRoot         = "/oauth/userinfo"
	routeAuthorizeNamespaced  = "/oauth/:" + encodedNamespacePathParam + "/authorize"
	routeTokenNamespaced      = "/oauth/:" + encodedNamespacePathParam + "/token"
	routeUserinfoNamespaced   = "/oauth/:" + encodedNamespacePathParam + "/userinfo"
	wellKnownOAuthServerPath  = "/.well-known/oauth-authorization-server"
	wellKnownOpenIDPath       = "/.well-known/openid-configuration"
	jwksPath                  = "/.well-known/jwks.json"

	// subjectTypePublic is the only OpenID subject type a3s exposes: the
	// subject claim is not pairwise per client.
	subjectTypePublic = "public"

	// signingAlgES256 is the algorithm the a3s token machinery uses to sign
	// the JWTs advertised through jwks_uri.
	signingAlgES256 = "ES256"
)

// RegisterRoutes installs the OAuth HTTP routes in Bahamut.
func RegisterRoutes(server bahamut.Server, handler *HTTPHandler) error {
	for _, route := range handler.routes() {
		if err := server.RegisterCustomRouteHandler(route, handler.ServeHTTP); err != nil {
			return fmt.Errorf("register oauth route %s: %w", route, err)
		}
	}

	return nil
}

func baseOAuthRoutes() []string {
	return []string{
		routeAuthorizeRoot,
		routeTokenRoot,
		routeUserinfoRoot,
		routeAuthorizeNamespaced,
		routeTokenNamespaced,
		routeUserinfoNamespaced,
	}
}

// HTTPHandler serves the OAuth protocol endpoints.
type HTTPHandler struct {
	oauth      *OAuth
	uiEndpoint string
	baseURL    *url.URL

	// issuerPath is the path component of the issuer, and so the prefix every
	// route appended to the issuer shares.
	issuerPath string

	authorizationServerRoute string

	// openIDConfigurationRoute is the RFC 8414 flavored discovery route,
	// where the well-known path is inserted before the issuer path.
	openIDConfigurationRoute string

	// issuerOpenIDConfigurationRoute is the OpenID Connect Discovery 1.0
	// flavored route, where the well-known path is appended to the issuer.
	issuerOpenIDConfigurationRoute string
}

// NewHTTPHandler returns a new HTTPHandler.
func NewHTTPHandler(
	oauth *OAuth,
	uiEndpoint string,
) *HTTPHandler {
	baseURL := *oauth.issuerURL
	baseURL.Path = ""
	baseURL.RawPath = ""
	baseURL.RawQuery = ""
	baseURL.Fragment = ""
	issuerPath := oauth.issuerURL.EscapedPath()
	return &HTTPHandler{
		oauth:                          oauth,
		uiEndpoint:                     uiEndpoint,
		baseURL:                        &baseURL,
		issuerPath:                     issuerPath,
		authorizationServerRoute:       wellKnownOAuthServerPath + issuerPath,
		openIDConfigurationRoute:       wellKnownOpenIDPath + issuerPath,
		issuerOpenIDConfigurationRoute: issuerPath + wellKnownOpenIDPath,
	}
}

// routes returns the route patterns served by the OAuth handler.
func (h *HTTPHandler) routes() []string {
	routes := append([]string{}, baseOAuthRoutes()...)
	routes = append(routes,
		h.authorizationServerRoute,
		h.authorizationServerRoute+"/:"+encodedNamespacePathParam,
		h.openIDConfigurationRoute,
		h.openIDConfigurationRoute+"/:"+encodedNamespacePathParam,
		h.issuerOpenIDConfigurationRoute,
		h.issuerPath+"/:"+encodedNamespacePathParam+wellKnownOpenIDPath,
	)
	return routes
}

// ServeHTTP dispatches requests to the authorize or token endpoint.
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	namespace, err := requestNamespace(req)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid namespace")
		return
	}

	switch {
	case req.URL.Path == h.authorizationServerRoute || strings.HasPrefix(req.URL.Path, h.authorizationServerRoute+"/"):
		h.handleAuthorizationServerMetadata(w, req, namespace)
	case req.URL.Path == h.openIDConfigurationRoute,
		strings.HasPrefix(req.URL.Path, h.openIDConfigurationRoute+"/"),
		strings.HasPrefix(req.URL.Path, h.issuerPath) && strings.HasSuffix(req.URL.Path, wellKnownOpenIDPath):
		h.handleOpenIDConfiguration(w, req, namespace)
	case strings.HasSuffix(req.URL.Path, "/authorize"):
		h.handleAuthorize(w, req, namespace)
	case strings.HasSuffix(req.URL.Path, "/token"):
		h.handleToken(w, req, namespace)
	case strings.HasSuffix(req.URL.Path, "/userinfo"):
		h.handleUserinfo(w, req, namespace)
	default:
		http.NotFound(w, req)
	}
}

func (h *HTTPHandler) handleAuthorize(w http.ResponseWriter, req *http.Request, namespace string) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "authorize endpoint only accepts GET or POST")
		return
	}
	if hasDuplicateOAuthParameters(req.URL.Query(), nil) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request parameters must not be duplicated")
		return
	}

	params := req.URL.Query()
	if req.Method == http.MethodPost {
		if err := req.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
			return
		}
		if hasDuplicateOAuthParameters(req.URL.Query(), req.PostForm) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request parameters must not be duplicated")
			return
		}
		params = req.Form
	}

	clientID := params.Get("client_id")
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing client_id")
		return
	}

	client, err := h.oauth.getClient(req.Context(), namespace, clientID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "unknown client_id")
		return
	}

	redirectURI, err := validateAuthorizeRedirectURI(client, params.Get("redirect_uri"))
	if err != nil {
		if code, description, ok := protocolErrorDetails(err); ok {
			writeOAuthError(w, http.StatusBadRequest, code, description)
			return
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect uri")
		return
	}

	state := params.Get("state")
	app, err := h.oauth.getOAuthApplication(req.Context(), client.Namespace, client.OauthApplicationID)
	if err != nil {
		redirectAuthorizeError(w, req, redirectURI, "unauthorized_client", "unknown oauth application", state)
		return
	}
	if app.Disabled {
		redirectAuthorizeError(w, req, redirectURI, "unauthorized_client", "oauth application is disabled", state)
		return
	}

	authorizeRequest, err := buildAuthorizeRequest(namespace, client, params, redirectURI)
	if err != nil {
		if code, description, ok := protocolErrorDetails(err); ok {
			redirectAuthorizeError(w, req, redirectURI, code, description, state)
			return
		}
		redirectAuthorizeError(w, req, redirectURI, "invalid_request", "invalid authorize request", state)
		return
	}

	if len(authorizeRequest.RequestedScopes) == 0 {
		authorizeRequest.RequestedScopes = append([]string{}, app.DefaultScopes...)
		if !containsAll(client.Scopes, authorizeRequest.RequestedScopes) {
			redirectAuthorizeError(w, req, redirectURI, "invalid_scope", "invalid scope", state)
			return
		}
	}

	contextID, err := generateAuthorizeContextID()
	if err != nil {
		redirectAuthorizeError(w, req, redirectURI, "server_error", "server error", state)
		return
	}

	authorizeContext := &AuthorizeContext{
		ID:               contextID,
		AuthorizeRequest: *authorizeRequest,
		ExpiresAtUnix:    time.Now().UTC().Add(5 * time.Minute).Unix(),
	}

	if err := h.oauth.store.createAuthorizeContext(authorizeContext); err != nil {
		redirectAuthorizeError(w, req, redirectURI, "server_error", "server error", state)
		return
	}

	continueURL := h.buildContinueURL(authorizeContext)
	http.Redirect(w, req, continueURL, http.StatusFound)
}

func (h *HTTPHandler) handleToken(w http.ResponseWriter, req *http.Request, namespace string) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "token endpoint only accepts POST")
		return
	}

	contentType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token endpoint requires application/x-www-form-urlencoded")
		return
	}

	if err := req.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
		return
	}
	if hasDuplicateOAuthParameters(req.URL.Query(), req.PostForm) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request parameters must not be duplicated")
		return
	}

	clientID := req.PostForm.Get("client_id")
	clientSecret := req.PostForm.Get("client_secret")
	clientAuthMethod := api.OAuthClientTokenEndpointAuthMethodNone

	basicClientID, basicClientSecret, hasBasicAuth := req.BasicAuth()
	if hasBasicAuth {
		if clientID != "" || clientSecret != "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "multiple client authentication methods used")
			return
		}
		clientID = decodeBasicClientID(basicClientID)
		clientSecret = basicClientSecret
		clientAuthMethod = api.OAuthClientTokenEndpointAuthMethodClientSecretBasic
	} else if clientSecret != "" {
		clientAuthMethod = api.OAuthClientTokenEndpointAuthMethodClientSecretPost
	}

	tokenRequest := TokenRequest{
		GrantType:        req.PostForm.Get("grant_type"),
		Code:             req.PostForm.Get("code"),
		RedirectURI:      req.PostForm.Get("redirect_uri"),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		ClientAuthMethod: clientAuthMethod,
		CodeVerifier:     req.PostForm.Get("code_verifier"),

		SubjectToken:       req.PostForm.Get("subject_token"),
		SubjectTokenType:   req.PostForm.Get("subject_token_type"),
		RequestedTokenType: req.PostForm.Get("requested_token_type"),
		ActorToken:         req.PostForm.Get("actor_token"),
		ActorTokenType:     req.PostForm.Get("actor_token_type"),
		Audience:           req.PostForm.Get("audience"),
		Resource:           req.PostForm.Get("resource"),
	}

	result, err := h.oauth.exchangeToken(req.Context(), namespace, tokenRequest)
	if err != nil {
		code, description := oauthErrorDetails(err)
		status := http.StatusBadRequest
		if code == "invalid_client" && hasBasicAuth {
			status = http.StatusUnauthorized
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		}
		writeOAuthError(w, status, code, description)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, result)
}

func (h *HTTPHandler) handleUserinfo(w http.ResponseWriter, req *http.Request, namespace string) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "userinfo endpoint only accepts GET or POST")
		return
	}

	// deliberately not using token.FromHTTPRequest, which falls back to the
	// x-a3s-token cookie which we shouldn't support in this flow
	accessToken, err := bearerToken(req)
	if err != nil {
		writeBearerError(w, "", "userinfo endpoint requires a bearer access token")
		return
	}

	claims, err := h.oauth.userinfo(namespace, accessToken)
	if err != nil {
		code, description, ok := protocolErrorDetails(err)
		if !ok {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "server error")
			return
		}
		writeBearerError(w, code, description)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, claims)
}

func bearerToken(req *http.Request) (string, error) {
	header := req.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("missing authorization header")
	}

	scheme, credential, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, tokenTypeBearer) {
		return "", errors.New("authorization header is not a bearer credential")
	}

	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", errors.New("empty bearer credential")
	}

	return credential, nil
}

func writeBearerError(w http.ResponseWriter, code string, description string) {
	challenge := `Bearer realm="oauth"`
	if code != "" {
		challenge = fmt.Sprintf(`Bearer realm="oauth", error=%q`, code)
	}

	w.Header().Set("WWW-Authenticate", challenge)

	if code == "" {
		code = "invalid_request"
	}

	writeOAuthError(w, http.StatusUnauthorized, code, description)
}

func (h *HTTPHandler) handleAuthorizationServerMetadata(w http.ResponseWriter, req *http.Request, namespace string) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "authorization server metadata endpoint only accepts GET")
		return
	}

	writeJSON(w, http.StatusOK, h.serverMetadata(namespace))
}

func (h *HTTPHandler) handleOpenIDConfiguration(w http.ResponseWriter, req *http.Request, namespace string) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "openid configuration endpoint only accepts GET")
		return
	}

	writeJSON(w, http.StatusOK, openIDProviderMetadata{
		authorizationServerMetadata:      h.serverMetadata(namespace),
		UserinfoEndpoint:                 h.oauth.issuerForNamespace(namespace) + "/userinfo",
		SubjectTypesSupported:            []string{subjectTypePublic},
		IDTokenSigningAlgValuesSupported: []string{signingAlgES256},
	})
}

func (h *HTTPHandler) serverMetadata(namespace string) authorizationServerMetadata {
	issuer := h.oauth.issuerForNamespace(namespace)

	jwksURI := *h.baseURL
	jwksURI.Path = jwksPath
	jwksURI.RawPath = ""
	jwksURI.RawQuery = ""

	return authorizationServerMetadata{
		Issuer:                        issuer,
		AuthorizationEndpoint:         issuer + "/authorize",
		TokenEndpoint:                 issuer + "/token",
		JWKSURI:                       jwksURI.String(),
		ResponseTypesSupported:        []string{oauthResponseTypeCode},
		ResponseModesSupported:        []string{"query"},
		GrantTypesSupported:           []string{oauthGrantTypeAuthorizationCode, oauthGrantTypeTokenExchange},
		CodeChallengeMethodsSupported: []string{pkceMethodS256},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
	}
}

func requestNamespace(req *http.Request) (string, error) {
	encodedNamespace := bone.GetValue(req, encodedNamespacePathParam)
	if encodedNamespace == "" {
		return "/", nil
	}

	return decodeNamespace(encodedNamespace)
}

func oauthErrorDetails(err error) (string, string) {
	if code, description, ok := protocolErrorDetails(err); ok {
		return code, description
	}

	if errors.Is(err, ErrAuthorizationCodeExpired) {
		return "invalid_grant", ErrAuthorizationCodeExpired.Error()
	}

	return "invalid_grant", "token exchange failed"
}

func writeOAuthError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func redirectAuthorizeError(w http.ResponseWriter, req *http.Request, redirectURI string, code string, description string, state string) {
	redirect, _ := url.Parse(redirectURI)
	query := redirect.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(w, req, redirect.String(), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func hasDuplicateOAuthParameters(query url.Values, form url.Values) bool {
	for key := range query {
		if len(query[key]) > 1 {
			return true
		}
		if _, ok := form[key]; ok {
			return true
		}
	}
	for key := range form {
		if len(form[key]) > 1 {
			return true
		}
	}

	return false
}

func generateAuthorizeContextID() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

func (h *HTTPHandler) buildContinueURL(authorizeContext *AuthorizeContext) string {
	values := url.Values{}
	values.Set("authorizeRequestID", authorizeContext.ID)
	values.Set("namespace", authorizeContext.Namespace)

	base := h.uiEndpoint
	u, err := url.Parse(base)
	if base == "" || err != nil {
		return "/ui/login.html?" + values.Encode()
	}

	query := u.Query()
	for key, vals := range values {
		for _, value := range vals {
			query.Set(key, value)
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

// decodeBasicClientID percent-decodes the user-id of an HTTP Basic credential.
//
// RFC 7617 section 2 makes a raw ":" invalid in the user-id, since Basic splits
// on the first one, so RFC 6749 section 2.3.1 has the client percent-encode the
// client identifier and the secret before base64 encoding them. Decoding here
// is what lets a client identifier hold a ":" at all.
//
// A value that fails to decode is used verbatim, because clients that skip the
// encoding are common and their credential must keep working. For the same
// reason this only undoes percent escapes and leaves "+" alone.
func decodeBasicClientID(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}

	return decoded
}
