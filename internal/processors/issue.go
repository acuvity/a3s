package processors

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/karlseguin/ccache/v3"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	"go.acuvity.ai/a3s/internal/issuer/a3sissuer"
	"go.acuvity.ai/a3s/internal/issuer/awsissuer"
	"go.acuvity.ai/a3s/internal/issuer/azureissuer"
	"go.acuvity.ai/a3s/internal/issuer/gcpissuer"
	"go.acuvity.ai/a3s/internal/issuer/httpissuer"
	"go.acuvity.ai/a3s/internal/issuer/ldapissuer"
	"go.acuvity.ai/a3s/internal/issuer/mtlsissuer"
	"go.acuvity.ai/a3s/internal/issuer/oauth2issuer"
	"go.acuvity.ai/a3s/internal/issuer/oidcissuer"
	"go.acuvity.ai/a3s/internal/issuer/remotea3sissuer"
	"go.acuvity.ai/a3s/internal/issuer/samlissuer"
	"go.acuvity.ai/a3s/internal/oauth2ceremony"
	"go.acuvity.ai/a3s/internal/oauth2ceremony/oauth2provider"
	"go.acuvity.ai/a3s/internal/samlceremony"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/auditor"
	"go.acuvity.ai/a3s/pkgs/modifier/binary"
	"go.acuvity.ai/a3s/pkgs/modifier/plugin"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/bahamut/authorizer/mtls"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/tg/tglib"
	"golang.org/x/oauth2"
)

// A IssueProcessor is a bahamut processor for Issue.
type IssueProcessor struct {
	manipulator          manipulate.Manipulator
	pluginModifier       plugin.Modifier
	binaryModifier       *binary.Modifier
	jwks                 *token.JWKS
	audience             string
	cookieDomain         string
	issuer               string
	mtlsHeaderKey        string
	mtlsHeaderPass       string
	maxValidity          time.Duration
	defaultValidity      time.Duration
	cookieSameSitePolicy http.SameSite
	mtlsHeaderEnabled    bool
	forbiddenOpaqueKeys  map[string]struct{}
	waiveSecret          string
	samlIDPMedataCache   *ccache.Cache[string]
}

// NewIssueProcessor returns a new IssueProcessor.
func NewIssueProcessor(
	manipulator manipulate.Manipulator,
	jwks *token.JWKS,
	defaultValidity time.Duration,
	maxValidity time.Duration,
	issuer string,
	audience string,
	forbiddenOpaqueKeys []string,
	waiveSecret string,
	cookieSameSitePolicy http.SameSite,
	cookieDomain string,
	mtlsHeaderEnabled bool,
	mtlsHeaderKey string,
	mtlsHeaderPass string,
	pluginModifier plugin.Modifier,
	binaryModifier *binary.Modifier,
) *IssueProcessor {

	// Make a map for fast lookups.
	fKeys := make(map[string]struct{}, len(forbiddenOpaqueKeys))
	for _, k := range forbiddenOpaqueKeys {
		fKeys[k] = struct{}{}
	}

	return &IssueProcessor{
		manipulator:          manipulator,
		jwks:                 jwks,
		defaultValidity:      defaultValidity,
		maxValidity:          maxValidity,
		issuer:               issuer,
		audience:             audience,
		cookieSameSitePolicy: cookieSameSitePolicy,
		cookieDomain:         cookieDomain,
		mtlsHeaderEnabled:    mtlsHeaderEnabled,
		mtlsHeaderKey:        mtlsHeaderKey,
		mtlsHeaderPass:       mtlsHeaderPass,
		pluginModifier:       pluginModifier,
		binaryModifier:       binaryModifier,
		waiveSecret:          waiveSecret,
		forbiddenOpaqueKeys:  fKeys,
		samlIDPMedataCache:   ccache.New(ccache.Configure[string]().MaxSize(2048)),
	}
}

// ProcessCreate handles the creates requests for Issue.
func (p *IssueProcessor) ProcessCreate(bctx bahamut.Context) (err error) {

	req := bctx.InputData().(*api.Issue)

	validity, _ := time.ParseDuration(req.Validity) // elemental already validated this

	validitySecretWaved := p.waiveSecret != "" && req.WaiveValiditySecret == p.waiveSecret

	if validity > p.maxValidity && !validitySecretWaved {
		return elemental.NewError(
			"Invalid validity",
			fmt.Sprintf("The requested validity '%s' is greater than the maximum allowed ('%s')", req.Validity, p.maxValidity),
			"a3s:authn",
			http.StatusBadRequest,
		)
	}

	if validity == 0 {
		validity = p.defaultValidity
	}

	if len(p.forbiddenOpaqueKeys) > 0 && len(req.Opaque) > 0 && !validitySecretWaved {
		for k := range req.Opaque {
			if _, ok := p.forbiddenOpaqueKeys[k]; ok {
				return elemental.NewError(
					"Invalid opaque key",
					fmt.Sprintf("The A3S administrator forbids the use of the opaque key '%s'", k),
					"a3s:authn",
					http.StatusBadRequest,
				)
			}
		}
	}

	exp := time.Now().Add(validity)

	audience := req.Audience
	if len(audience) == 0 {
		audience = jwt.ClaimStrings{p.audience}
	}

	var issuer token.Issuer

	switch req.SourceType {

	case api.IssueSourceTypeMTLS:
		issuer, err = p.handleCertificateIssue(
			bctx.Context(),
			req,
			bctx.Request().TLSConnectionState,
			bctx.Request().Headers.Get(p.mtlsHeaderKey),
		)

	case api.IssueSourceTypeLDAP:
		issuer, err = p.handleLDAPIssue(bctx.Context(), req)

	case api.IssueSourceTypeHTTP:
		issuer, err = p.handleHTTPIssue(bctx.Context(), req)

	case api.IssueSourceTypeAWS:
		issuer, err = p.handleAWSIssue(req)

	case api.IssueSourceTypeAzure:
		issuer, err = p.handleAzureIssue(bctx.Context(), req)

	case api.IssueSourceTypeGCP:
		issuer, err = p.handleGCPIssue(req)

	case api.IssueSourceTypeRemoteA3S:
		issuer, err = p.handleRemoteA3SIssue(bctx.Context(), req)

	case api.IssueSourceTypeOIDC:
		issuer, err = p.handleOIDCIssue(bctx, req)
		if issuer == nil && err == nil {
			return nil
		}

	case api.IssueSourceTypeOAuth2:
		issuer, err = p.handleOAuth2Issue(bctx, req)
		if issuer == nil && err == nil {
			return nil
		}

	case api.IssueSourceTypeSAML:
		issuer, err = p.handleSAMLIssue(bctx, req)
		if issuer == nil && err == nil {
			return nil
		}

	case api.IssueSourceTypeA3S:
		if req.Validity == "" {
			validity = 0
		}
		issuer, err = p.handleTokenIssue(req, validity, audience)
		// we reset to 0 to skip setting exp during issuing of the token
		// as the token issers already caps it.
		if p.waiveSecret != req.WaiveValiditySecret {
			exp = time.Time{}
		}
	}

	if err != nil {
		return elemental.NewError("Unauthorized", err.Error(), "a3s:authn", http.StatusUnauthorized)
	}

	idt := issuer.Issue()
	idt.Opaque = req.Opaque

	defer func() {
		bctx.SetMetadata(auditor.MetadataKeyAudit, idt.Identity)
	}()

	if err := idt.Restrict(permissions.Restrictions{
		Namespace:   req.RestrictedNamespace,
		Networks:    req.RestrictedNetworks,
		Permissions: req.RestrictedPermissions,
	}); err != nil {
		return elemental.NewError(
			"Restrictions Error",
			err.Error(),
			"a3s:authn",
			http.StatusBadRequest,
		)
	}

	if req.TokenType == api.IssueTokenTypeRefresh {
		idt.Refresh = true
	}

	originalSource := idt.Source
	if p.pluginModifier != nil {
		if idt, err = p.pluginModifier.Token(bctx.Context(), p.manipulator, idt, p.issuer); err != nil {
			return fmt.Errorf("modifier: plugin: unable to run Token: %w", err)
		}
	}

	if p.binaryModifier != nil {
		if idt, err = p.binaryModifier.Write(bctx.Context(), idt, p.issuer); err != nil {
			return fmt.Errorf("modifier: binary: unable to run Write: %w", err)
		}
	}
	idt.Source = originalSource

	k := p.jwks.GetLastWithPrivate()
	tkn, err := idt.JWT(k.PrivateKey(), k.KID, p.issuer, audience, exp, req.Cloak)
	if err != nil {
		return fmt.Errorf("unable to sign jwt: %w", err)
	}

	req.Validity = time.Until(idt.ExpiresAt.Time).Round(time.Second).String()
	req.ExpirationTime = idt.ExpiresAt.Time
	req.Claims = idt.Identity
	req.InputLDAP = nil
	req.InputAWS = nil
	req.InputAzure = nil
	req.InputGCP = nil
	req.InputOIDC = nil
	req.InputA3S = nil
	req.InputRemoteA3S = nil
	req.InputOAuth2 = nil

	if req.Cookie {
		domain := req.CookieDomain
		if domain == "" {
			domain = p.cookieDomain
		}
		c := &http.Cookie{
			Name:     "x-a3s-token",
			Value:    tkn,
			HttpOnly: true,
			Secure:   true,
			Expires:  idt.ExpiresAt.Time,
			SameSite: p.cookieSameSitePolicy,
			Path:     "/",
			Domain:   domain,
		}
		if err := c.Valid(); err != nil {
			slog.Error("Cookie about to be delivered is not valid", err)
		}
		bctx.AddOutputCookies(c)
	} else {
		req.Token = tkn
	}

	bctx.SetOutputData(req)

	return nil
}

func (p *IssueProcessor) handleCertificateIssue(ctx context.Context, req *api.Issue, tlsState *tls.ConnectionState, tlsHeader string) (token.Issuer, error) {

	// We get the peer certificate.
	var certs []*x509.Certificate

	// If mtls header is enabled, and the header is not empty
	// we will use it instead of the cert from the tls state.
	if p.mtlsHeaderEnabled && tlsHeader != "" {

		// First we create an elemental.AESAttributeEncrypter
		cipher, err := elemental.NewAESAttributeEncrypter(p.mtlsHeaderPass)
		if err != nil {
			return nil, fmt.Errorf("unable to build AES encrypter: %w", err)
		}

		// Then we decrypt the content of the header.
		header, err := cipher.DecryptString(tlsHeader)
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt header: %w", err)
		}

		// Then we try to extract a certificate out of the decrypted blob.
		certs, err = mtls.CertificatesFromHeader(header)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve certificate from mtls header: %w", err)
		}

		// If we reach here, the decoded certificate from the header will be used to
		// to match against the source.
	} else {
		certs = tlsState.PeerCertificates
	}

	if len(certs) == 0 {
		return nil, elemental.NewError("Bad Request", "No user certificates", "a3s:authn", http.StatusBadRequest)
	}

	out, err := retrieveSource(ctx, p.manipulator, req.SourceNamespace, req.SourceName, api.MTLSSourceIdentity)
	if err != nil {
		return nil, err
	}
	src := out.(*api.MTLSSource)

	iss, err := mtlsissuer.New(ctx, src, certs[0])
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleLDAPIssue(ctx context.Context, req *api.Issue) (token.Issuer, error) {

	out, err := retrieveSource(ctx, p.manipulator, req.SourceNamespace, req.SourceName, api.LDAPSourceIdentity)
	if err != nil {
		return nil, err
	}

	src := out.(*api.LDAPSource)
	iss, err := ldapissuer.New(ctx, src, req.InputLDAP.Username, req.InputLDAP.Password)
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleHTTPIssue(ctx context.Context, req *api.Issue) (token.Issuer, error) {

	out, err := retrieveSource(ctx, p.manipulator, req.SourceNamespace, req.SourceName, api.HTTPSourceIdentity)
	if err != nil {
		return nil, err
	}

	src := out.(*api.HTTPSource)
	iss, err := httpissuer.New(ctx, src, httpissuer.Credentials{
		Username: req.InputHTTP.Username,
		Password: req.InputHTTP.Password,
		TOTP:     req.InputHTTP.TOTP,
	})
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleAWSIssue(req *api.Issue) (token.Issuer, error) {

	iss, err := awsissuer.New(req.InputAWS.ID, req.InputAWS.Secret, req.InputAWS.Token)
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleAzureIssue(ctx context.Context, req *api.Issue) (token.Issuer, error) {

	iss, err := azureissuer.New(ctx, req.InputAzure.Token)
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleGCPIssue(req *api.Issue) (token.Issuer, error) {

	iss, err := gcpissuer.New(req.InputGCP.Token, req.InputGCP.Audience)
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleTokenIssue(req *api.Issue, validity time.Duration, audience []string) (token.Issuer, error) {

	iss, err := a3sissuer.New(
		req.InputA3S.Token,
		p.jwks,
		p.issuer,
		audience,
		validity,
		req.WaiveValiditySecret == p.waiveSecret,
	)
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleRemoteA3SIssue(ctx context.Context, req *api.Issue) (token.Issuer, error) {

	out, err := retrieveSource(ctx, p.manipulator, req.SourceNamespace, req.SourceName, api.A3SSourceIdentity)
	if err != nil {
		return nil, err
	}

	src := out.(*api.A3SSource)
	iss, err := remotea3sissuer.New(ctx, src, req.InputRemoteA3S.Token)
	if err != nil {
		return nil, err
	}

	return iss, nil
}

func (p *IssueProcessor) handleOIDCIssue(bctx bahamut.Context, req *api.Issue) (token.Issuer, error) {

	input := req.InputOIDC
	state := input.State
	code := input.Code

	out, err := retrieveSource(bctx.Context(), p.manipulator, req.SourceNamespace, req.SourceName, api.OIDCSourceIdentity)
	if err != nil {
		return nil, err
	}

	src := out.(*api.OIDCSource)

	rerr := oauth2ceremony.MakeRedirectError(bctx, input.RedirectErrorURL)

	if code == "" && state == "" {

		state, err = oauth2ceremony.GenerateNonce(12)
		if err != nil {
			return nil, rerr(fmt.Errorf("unable to generate nonce for oidc state: %w", err))
		}

		client, err := oauth2ceremony.MakeClient(src.CA)
		if err != nil {
			return nil, rerr(elemental.NewError("Bad Request", err.Error(), "a3s:authn", http.StatusBadRequest))
		}

		ctx := oidc.ClientContext(bctx.Context(), client)
		provider, err := oidc.NewProvider(ctx, src.Endpoint)
		if err != nil {
			return nil, rerr(elemental.NewError("Bad Request", err.Error(), "a3s:authn", http.StatusBadRequest))
		}

		oauth2Config := oauth2.Config{
			ClientID:     src.ClientID,
			ClientSecret: src.ClientSecret,
			RedirectURL:  input.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       append([]string{oidc.ScopeOpenID}, src.Scopes...),
		}

		cacheItem := &oauth2ceremony.CacheItem{
			State:        state,
			OAuth2Config: oauth2Config,
		}

		if err := oauth2ceremony.Set(p.manipulator, cacheItem); err != nil {
			return nil, rerr(fmt.Errorf("unabelt to set oidc cache: %w", err))
		}

		authURL := oauth2Config.AuthCodeURL(state)

		if input.NoAuthRedirect {
			input.AuthURL = authURL
			bctx.SetOutputData(req)
		} else {
			bctx.SetRedirect(authURL)
		}

		return nil, nil
	}

	cached, err := oauth2ceremony.Get(p.manipulator, state)
	if err != nil {
		return nil, rerr(fmt.Errorf("unable to retrieve cached oidc state: %w", err))
	}

	if err := oauth2ceremony.Delete(p.manipulator, state); err != nil {
		return nil, rerr(fmt.Errorf("unable to delete cached oidc state: %w", err))
	}

	client, err := oauth2ceremony.MakeClient(src.CA)
	if err != nil {
		return nil, rerr(fmt.Errorf("unable to create oidc http client: %w", err))
	}

	ctx := oidc.ClientContext(bctx.Context(), client)

	tok, err := cached.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, rerr(elemental.NewError("OAuth2 Error", err.Error(), "a3s:authn", http.StatusNotAcceptable))
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing ID token")
	}

	provider, err := oidc.NewProvider(ctx, src.Endpoint)
	if err != nil {
		return nil, rerr(elemental.NewError("OIDC Error", err.Error(), "a3s:authn", http.StatusUnauthorized))
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: src.ClientID})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, rerr(elemental.NewError("OAuth2 Verification Error", err.Error(), "a3s:authn", http.StatusNotAcceptable))
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, rerr(elemental.NewError("Claims Decoding Error", err.Error(), "a3s:authn", http.StatusNotAcceptable))
	}

	return oidcissuer.New(bctx.Context(), src, claims)
}

func (p *IssueProcessor) handleOAuth2Issue(bctx bahamut.Context, req *api.Issue) (token.Issuer, error) {

	input := req.InputOAuth2
	state := input.State
	code := input.Code

	out, err := retrieveSource(bctx.Context(), p.manipulator, req.SourceNamespace, req.SourceName, api.OAuth2SourceIdentity)
	if err != nil {
		return nil, err
	}

	src := out.(*api.OAuth2Source)

	provider := oauth2provider.Get(src.Provider)
	if provider == nil {
		return nil, fmt.Errorf("OAuth2 provider %s is not implemented yet", src.Provider)
	}

	rerr := oauth2ceremony.MakeRedirectError(bctx, input.RedirectErrorURL)

	if code == "" && state == "" {

		state, err = oauth2ceremony.GenerateNonce(12)
		if err != nil {
			return nil, rerr(fmt.Errorf("unable to generate oauth2 state: %w", err))
		}

		conf := oauth2.Config{
			ClientID:     src.ClientID,
			ClientSecret: src.ClientSecret,
			Scopes:       src.Scopes,
			RedirectURL:  input.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  provider.AuthURL(),
				TokenURL: provider.TokenURL(),
			},
		}

		cacheItem := &oauth2ceremony.CacheItem{
			State:        state,
			OAuth2Config: conf,
		}

		if err := oauth2ceremony.Set(p.manipulator, cacheItem); err != nil {
			return nil, rerr(fmt.Errorf("unable to cache oauth2 state: %w", err))
		}

		authURL := conf.AuthCodeURL(state)

		if input.NoAuthRedirect {
			input.AuthURL = authURL
			bctx.SetOutputData(req)
		} else {
			bctx.SetRedirect(authURL)
		}

		return nil, nil
	}

	cached, err := oauth2ceremony.Get(p.manipulator, input.State)
	if err != nil {
		return nil, rerr(fmt.Errorf("unable to retrieve cached oauth2 state: %w", err))
	}

	if err := oauth2ceremony.Delete(p.manipulator, state); err != nil {
		return nil, rerr(fmt.Errorf("unable to delete cached oauth2 state: %w", err))
	}

	conf := cached.OAuth2Config

	client, err := oauth2ceremony.MakeClient(src.CA)
	if err != nil {
		return nil, rerr(elemental.NewError("Internal Server Error", fmt.Sprintf("oauth2: unable to make provider client: %s", err), "a3s:authn", http.StatusInternalServerError))
	}

	ctx := context.WithValue(bctx.Context(), oauth2.HTTPClient, client)
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		return nil, rerr(elemental.NewError("Unauthorized", fmt.Sprintf("oauth2: unable to exchange code for access token: %s", err), "a3s:authn", http.StatusUnauthorized))
	}

	claims, err := provider.RetrieveClaims(conf.Client(ctx, tok))
	if err != nil {
		return nil, rerr(elemental.NewError("Unauthorized", fmt.Sprintf("oauth2: unable to retrieve claims: %s", err), "a3s:authn", http.StatusUnauthorized))
	}

	return oauth2issuer.New(bctx.Context(), src, claims)
}

func (p *IssueProcessor) handleSAMLIssue(bctx bahamut.Context, req *api.Issue) (token.Issuer, error) {

	input := req.InputSAML
	out, err := retrieveSource(
		bctx.Context(),
		p.manipulator,
		req.SourceNamespace,
		req.SourceName,
		api.SAMLSourceIdentity,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve saml source '%s' in namespace '%s': %w", req.SourceName, req.SourceNamespace, err)
	}
	src := out.(*api.SAMLSource)
	rerr := samlceremony.MakeRedirectError(bctx, input.RedirectErrorURL)

	serviceProviderIssuer := src.ServiceProviderIssuer
	if serviceProviderIssuer == "" {
		serviceProviderIssuer = p.issuer
	}

	if err := samlissuer.InjectRemoteIDPMetadata(src, p.samlIDPMedataCache); err != nil {
		return nil, fmt.Errorf("unable to populate IDP metadata from the source IDPMetadataURL: %w", err)
	}

	if input.SAMLResponse == "" && input.RelayState == "" {

		sp := &saml2.SAMLServiceProvider{
			IdentityProviderSSOURL:      src.IDPURL,
			IdentityProviderIssuer:      src.IDPIssuer,
			ServiceProviderIssuer:       serviceProviderIssuer,
			AudienceURI:                 p.issuer,
			AssertionConsumerServiceURL: input.RedirectURL,
			SPKeyStore:                  dsig.RandomKeyStoreForTest(),
			AllowMissingAttributes:      true,
			SignAuthnRequests:           true,
		}

		if len(src.IDPCertificate) > 0 {
			certs, err := tglib.ParseCertificates([]byte(src.IDPCertificate))
			if err != nil {
				return nil, rerr(elemental.NewError("Bad Request", fmt.Sprintf("Unable to parse IDPCertificate: %s", err), "a3s", http.StatusBadRequest))
			}
			sp.IDPCertificateStore = &dsig.MemoryX509CertificateStore{Roots: certs}
		}

		state, err := samlceremony.GenerateNonce(12)
		if err != nil {
			return nil, rerr(fmt.Errorf("unable to generate relay state: %w", err))
		}

		authURL, err := sp.BuildAuthURL(state)
		if err != nil {
			return nil, rerr(fmt.Errorf("unable to build auth url: %w", err))
		}

		cacheItem := &samlceremony.CacheItem{
			State:  state,
			ACSURL: sp.AssertionConsumerServiceURL,
		}

		if err := samlceremony.Set(p.manipulator, cacheItem); err != nil {
			return nil, rerr(fmt.Errorf("unable to cache ceremony: %w", err))
		}

		if req.InputSAML.NoAuthRedirect {
			req.InputSAML.AuthURL = authURL
			bctx.SetOutputData(req)
		} else {
			bctx.SetRedirect(authURL)
		}

		return nil, nil
	}

	item, err := samlceremony.Get(p.manipulator, input.RelayState)
	if err != nil {
		return nil, rerr(elemental.NewError("SAML Error", "Unable to find SAML session. Did you wait too long?", "a3s", http.StatusForbidden))
	}

	if err := samlceremony.Delete(p.manipulator, input.RelayState); err != nil {
		return nil, rerr(fmt.Errorf("unable to clean saml ceremony cache: %w", err))
	}

	audienceURI := src.AudienceURI
	if audienceURI == "" {
		audienceURI = p.issuer
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      src.IDPURL,
		IdentityProviderIssuer:      src.IDPIssuer,
		ServiceProviderIssuer:       p.issuer,
		AudienceURI:                 audienceURI,
		AssertionConsumerServiceURL: item.ACSURL,
		SPKeyStore:                  dsig.RandomKeyStoreForTest(),
		AllowMissingAttributes:      true,
		SignAuthnRequests:           true,
	}

	if len(src.IDPCertificate) > 0 {
		certs, err := tglib.ParseCertificates([]byte(src.IDPCertificate))
		if err != nil {
			return nil, fmt.Errorf("unable to parse IDP certificates: %w", err)
		}
		sp.IDPCertificateStore = &dsig.MemoryX509CertificateStore{Roots: certs}
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(input.SAMLResponse)
	if err != nil {
		return nil, rerr(elemental.NewError("SAML Error", fmt.Sprintf("Unable to retrieve assertions: %s", err), "a3s", http.StatusForbidden))
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return nil, rerr(elemental.NewError("Forbidden", "Invalid assertion time", "a3s", http.StatusForbidden))
	}

	if assertionInfo.WarningInfo.OneTimeUse {
		return nil, rerr(elemental.NewError("Forbidden", "Invalid one time use", "a3s", http.StatusForbidden))
	}

	if !src.SkipResponseSignatureCheck && !assertionInfo.ResponseSignatureValidated {
		return nil, rerr(elemental.NewError("Forbidden", "Invalid response signature", "a3s", http.StatusForbidden))
	}

	if assertionInfo.WarningInfo.NotInAudience {
		return nil, rerr(elemental.NewError("Forbidden", "Invalid audience", "a3s", http.StatusForbidden))
	}

	return samlissuer.New(bctx.Context(), src, assertionInfo)
}

func retrieveSource(
	ctx context.Context,
	m manipulate.Manipulator,
	namespace string,
	name string,
	identity elemental.Identity,
) (elemental.Identifiable, error) {

	if namespace == "" {
		return nil, elemental.NewError(
			"Bad Request",
			"You must set sourceNamespace and sourceName",
			"a3s:auth",
			http.StatusBadRequest,
		)
	}

	if name == "" {
		return nil, elemental.NewError(
			"Bad Request",
			"You must set sourceNamespace and sourceName",
			"a3s:auth",
			http.StatusBadRequest,
		)
	}

	mctx := manipulate.NewContext(ctx,
		manipulate.ContextOptionNamespace(namespace),
		manipulate.ContextOptionFilter(
			elemental.NewFilterComposer().WithKey("name").Equals(name).
				Done(),
		),
	)

	identifiables := api.Manager().IdentifiablesFromString(identity.Name)
	if err := m.RetrieveMany(mctx, identifiables); err != nil {
		return nil, err
	}

	lst := identifiables.List()
	switch len(lst) {
	case 0:
		return nil, elemental.NewError(
			"Not Found",
			"Unable to find the request auth source",
			"a3s:authn",
			http.StatusNotFound,
		)
	case 1:
	default:
		return nil, fmt.Errorf("more than one auth source found")
	}

	return lst[0], nil
}
