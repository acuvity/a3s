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
	routeAuthorizeNamespaced  = "/oauth/:" + encodedNamespacePathParam + "/authorize"
	routeTokenNamespaced      = "/oauth/:" + encodedNamespacePathParam + "/token"
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
		routeAuthorizeNamespaced,
		routeTokenNamespaced,
	}
}

// HTTPHandler serves the OAuth protocol endpoints.
type HTTPHandler struct {
	oauth      *OAuth
	uiEndpoint string
}

// NewHTTPHandler returns a new HTTPHandler.
func NewHTTPHandler(
	oauth *OAuth,
	uiEndpoint string,
) *HTTPHandler {
	return &HTTPHandler{
		oauth:      oauth,
		uiEndpoint: uiEndpoint,
	}
}

// routes returns the route patterns served by the OAuth handler.
func (h *HTTPHandler) routes() []string {
	return append([]string{}, baseOAuthRoutes()...)
}

// ServeHTTP dispatches requests to the authorize or token endpoint.
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	namespace, err := requestNamespace(req)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid namespace")
		return
	}

	switch {
	case strings.HasSuffix(req.URL.Path, "/authorize"):
		h.handleAuthorize(w, req, namespace)
	case strings.HasSuffix(req.URL.Path, "/token"):
		h.handleToken(w, req, namespace)
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

	params := req.URL.Query()
	if req.Method == http.MethodPost {
		if err := req.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
			return
		}
		params = req.Form
	}

	clientID := params.Get("client_id")
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing client_id")
		return
	}

	client, err := h.oauth.store.getClient(req.Context(), namespace, clientID)
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

	app, err := h.oauth.store.getOAuthApplication(req.Context(), client.OauthApplicationNamespace, client.OauthApplicationID)
	if err != nil {
		redirectAuthorizeError(w, req, redirectURI, "unauthorized_client", "unknown oauth application", state)
		return
	}
	if !app.Enabled {
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
		ID:                        contextID,
		AuthorizeRequest:          *authorizeRequest,
		OAuthApplicationID:        client.OauthApplicationID,
		OAuthApplicationNamespace: client.OauthApplicationNamespace,
		ExpiresAt:                 time.Now().UTC().Add(5 * time.Minute),
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

	clientID := req.PostForm.Get("client_id")
	clientSecret := req.PostForm.Get("client_secret")
	clientAuthMethod := api.OAuthClientTokenEndpointAuthMethodNone

	basicClientID, basicClientSecret, hasBasicAuth := req.BasicAuth()
	if hasBasicAuth {
		if clientID != "" || clientSecret != "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "multiple client authentication methods used")
			return
		}
		clientID = basicClientID
		clientSecret = basicClientSecret
		clientAuthMethod = api.OAuthClientTokenEndpointAuthMethodClientSecretBasic
	} else if clientSecret != "" {
		clientAuthMethod = api.OAuthClientTokenEndpointAuthMethodClientSecretPost
	}

	if clientID == "" {
		if hasBasicAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "missing client authentication")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "missing client authentication")
		return
	}

	client, err := h.oauth.store.getClient(req.Context(), namespace, clientID)
	if err != nil {
		status := http.StatusBadRequest
		if hasBasicAuth {
			status = http.StatusUnauthorized
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		}
		writeOAuthError(w, status, "invalid_client", "unknown client_id")
		return
	}

	tokenRequest := TokenRequest{
		GrantType:        req.PostForm.Get("grant_type"),
		Code:             req.PostForm.Get("code"),
		RedirectURI:      req.PostForm.Get("redirect_uri"),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		ClientAuthMethod: clientAuthMethod,
		CodeVerifier:     req.PostForm.Get("code_verifier"),
	}

	accessToken, expiresIn, scopes, includeScope, err := h.oauth.exchangeToken(client, tokenRequest)
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
	response := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}
	if includeScope && len(scopes) > 0 {
		response["scope"] = strings.Join(scopes, " ")
	}
	writeJSON(w, http.StatusOK, response)
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
	if base == "" {
		return "/ui/login.html?" + values.Encode()
	}

	u, err := url.Parse(base)
	if err != nil {
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
