package authenticator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/karlseguin/ccache/v2"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

// A Authenticator is a bahamut.Authenticator compliant structure to authentify
// requests using an a3s token.
type Authenticator struct {
	jwks                   *token.JWKS
	externalTrustedIssuers map[string]RemoteIssuer
	ignoredResources       map[string]struct{}
	trustedJWKsCache       *ccache.Cache
	issuer                 string
	audience               string
}

// New returns a new Authenticator that will use the provided JWKS
// to cryptographically verify a request or session token.
// It will validate the token comes from the given issuer and has the
// correct audience.
func New(jwks *token.JWKS, issuer string, audience string, options ...Option) *Authenticator {

	cfg := config{}
	for _, o := range options {
		o(&cfg)
	}

	ignored := make(map[string]struct{}, len(cfg.ignoredResources))
	for _, r := range cfg.ignoredResources {
		ignored[r] = struct{}{}
	}

	trusted := make(map[string]RemoteIssuer, len(cfg.externalTrustedIssuers))
	for _, r := range cfg.externalTrustedIssuers {
		trusted[r.URL] = r
	}

	return &Authenticator{
		jwks:                   jwks,
		issuer:                 issuer,
		audience:               audience,
		ignoredResources:       ignored,
		externalTrustedIssuers: trusted,
		trustedJWKsCache:       ccache.New(ccache.Configure().MaxSize(1024)),
	}
}

// AuthenticateSession authenticates the given session.
func (a *Authenticator) AuthenticateSession(session bahamut.Session) (bahamut.AuthAction, error) {

	action, idt, err := a.CheckAuthentication(session.Context(), token.FromSession(session))
	if err != nil {
		return bahamut.AuthActionKO, err
	}

	session.SetClaims(idt.Identity)

	return action, nil
}

// AuthenticateRequest authenticates the request from the given bahamut.Context.
func (a *Authenticator) AuthenticateRequest(bctx bahamut.Context) (bahamut.AuthAction, error) {

	if _, ok := a.ignoredResources[bctx.Request().Identity.Category]; ok {
		return bahamut.AuthActionOK, nil
	}

	token := token.FromRequest(bctx.Request())

	action, idt, err := a.CheckAuthentication(bctx.Context(), token)
	if err != nil {
		return bahamut.AuthActionKO, err
	}

	bctx.SetClaims(idt.Identity)

	return action, nil
}

// CheckAuthentication authenticates the given JWT string.
func (a *Authenticator) CheckAuthentication(ctx context.Context, tokenString string) (bahamut.AuthAction, *token.IdentityToken, error) {

	if tokenString == "" {
		return bahamut.AuthActionKO, nil, elemental.NewError(
			"Unauthorized",
			"Missing token in Authorization header",
			"a3s:authn",
			http.StatusUnauthorized,
		)
	}

	jwks := a.jwks
	issuer := a.issuer

	rjwks, rissuer, err := a.handleFederatedToken(ctx, tokenString)
	if err != nil {
		return bahamut.AuthActionKO, nil, elemental.NewError(
			"Unauthorized",
			fmt.Sprintf("Unable to deal with eventually federated token: %s", err),
			"a3s:authn",
			http.StatusUnauthorized,
		)
	}
	if rjwks != nil && issuer != "" {
		jwks = rjwks
		issuer = rissuer
	}

	idt, err := token.Parse(tokenString, jwks, issuer, a.audience)
	if err != nil {
		return bahamut.AuthActionKO, nil, elemental.NewError(
			"Unauthorized",
			fmt.Sprintf("Authentication rejected with error: %s", err),
			"a3s:authn",
			http.StatusUnauthorized,
		)
	}

	if idt.Refresh {
		return bahamut.AuthActionKO, nil, elemental.NewError(
			"Unauthorized",
			"Authentication impossible from a refresh token",
			"a3s:authn",
			http.StatusUnauthorized,
		)
	}

	return bahamut.AuthActionContinue, idt, nil
}

func (a *Authenticator) handleFederatedToken(ctx context.Context, tokenString string) (jwks *token.JWKS, issuer string, err error) {

	// If we have no externalTrustedIssuers, this function is a noop.
	if len(a.externalTrustedIssuers) == 0 {
		return nil, "", nil
	}

	// Parse the token to extract the issuer.
	uidt, err := token.ParseUnverified(tokenString)
	if err != nil {
		return nil, "", fmt.Errorf("unable to parse input token: %w", err)
	}

	// If the issuer is the local one, we stop.
	// no need to go fetch our own JWKS.
	if a.issuer == uidt.Issuer {
		return nil, "", nil
	}

	// Prevent weird input.
	if uidt.Issuer == "*" {
		return nil, "", fmt.Errorf("invalid iss field in token: what are you trying to do here?")
	}

	// Check if the issuer is in the list, or the
	// list contains the wildcard '*'.
	remoteIssuer, ok1 := a.externalTrustedIssuers[uidt.Issuer]
	_, ok2 := a.externalTrustedIssuers["*"]
	if !ok1 && !ok2 {
		return nil, "", nil
	}

	// If it is cached, we return the cached JWKS.
	if item := a.trustedJWKsCache.Get(uidt.Issuer); item != nil && !item.Expired() {
		return item.Value().(*token.JWKS), uidt.Issuer, nil
	}

	// Then we build a tls.Config with the CA in preparation
	// of retrieving the remote JWKS.
	pool := remoteIssuer.Pool
	if pool == nil {
		if pool, err = x509.SystemCertPool(); err != nil {
			return nil, "", fmt.Errorf("unable to pull system cert pool: %w", err)
		}
	}

	// We go fetch the JWKS.
	if jwks, err = token.JWKSFromTokenIssuer(ctx, uidt, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}); err != nil {
		return nil, "", fmt.Errorf("unable to retrieve remote jwks: %w", err)
	}

	// And we cache it.
	a.trustedJWKsCache.Set(uidt.Issuer, jwks, time.Hour)

	return jwks, uidt.Issuer, nil
}
