package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	goplugin "plugin"

	"github.com/ghodss/yaml"
	"github.com/globalsign/mgo"
	"go.acuvity.ai/a3s/internal/hasher"
	"go.acuvity.ai/a3s/internal/processors"
	"go.acuvity.ai/a3s/internal/ui"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/auditor"
	"go.acuvity.ai/a3s/pkgs/authenticator"
	"go.acuvity.ai/a3s/pkgs/authorizer"
	"go.acuvity.ai/a3s/pkgs/bearermanip"
	"go.acuvity.ai/a3s/pkgs/bootstrap"
	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/a3s/pkgs/importing"
	"go.acuvity.ai/a3s/pkgs/indexes"
	"go.acuvity.ai/a3s/pkgs/jobs"
	"go.acuvity.ai/a3s/pkgs/modifier/binary"
	"go.acuvity.ai/a3s/pkgs/modifier/plugin"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/a3s/pkgs/nscache"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/push"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.acuvity.ai/tg/tglib"

	gwpush "go.acuvity.ai/bahamut/gateway/upstreamer/push"
)

var (
	publicResources = []string{
		api.IssueIdentity.Category,
		api.PermissionsIdentity.Category,
		api.AuthzIdentity.Category,
		api.LogoutIdentity.Category,
	}
	pushExcludedResources = []elemental.Identity{
		api.PermissionsIdentity,

		// safety: these ones are not an identifiable, so it would not be pushed anyway.
		api.IssueIdentity,
		api.AuthzIdentity,
		api.LogoutIdentity,
	}
)

func main() {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bahamut.InstallSIGINTHandler(cancel)

	cfg := newConf()

	if closeFunc := bootstrap.ConfigureLogger("a3s", cfg.LoggingConf); closeFunc != nil {
		defer closeFunc()
	}

	if cfg.InitDB {
		if err := createMongoDBAccount(cfg.MongoConf, cfg.InitDBUsername); err != nil {
			slog.Error("Unable to create mongodb account", err)
			os.Exit(1)
		}

		if !cfg.InitContinue {
			return
		}
	}

	m := bootstrap.MakeMongoManipulator(cfg.MongoConf, &hasher.Hasher{}, api.Manager())
	if err := indexes.Ensure(m, api.Manager(), "a3s"); err != nil {
		slog.Error("Unable to ensure indexes", err)
		os.Exit(1)
	}

	if err := manipmongo.EnsureIndex(m, elemental.MakeIdentity("oauth2cache", "oauth2cache"), mgo.Index{
		Key:         []string{"time"},
		ExpireAfter: 1 * time.Minute,
		Name:        "index_expiration_exp",
	}); err != nil {
		slog.Error("Unable to create exp expiration index for oauth2cache", err)
		os.Exit(1)
	}

	if err := manipmongo.EnsureIndex(m, elemental.MakeIdentity("samlcache", "samlcache"), mgo.Index{
		Key:         []string{"time"},
		ExpireAfter: 1 * time.Minute,
		Name:        "index_expiration_exp",
	}); err != nil {
		slog.Error("Unable to create exp expiration index for samlcache", err)
		os.Exit(1)
	}

	if err := manipmongo.EnsureIndex(m, api.NamespaceDeletionRecordIdentity, mgo.Index{
		Key:         []string{"deletetime"},
		ExpireAfter: 24 * time.Hour,
		Name:        "index_expiration_deletetime",
	}); err != nil {
		slog.Error("Unable to create expiration index for namesapce deletion records", err)
		os.Exit(1)
	}

	if err := manipmongo.EnsureIndex(m, api.RevocationIdentity, mgo.Index{
		Key:         []string{"expiration"},
		ExpireAfter: 1 * time.Minute,
		Name:        "index_revocation_expiration",
	}); err != nil {
		slog.Error("Unable to create revocation expiration index for expiration", err)
		os.Exit(1)
	}

	if err := createRootNamespaceIfNeeded(m); err != nil {
		slog.Error("Unable to handle root namespace", err)
		os.Exit(1)
	}

	if cfg.Init {
		if cfg.InitRootUserCAPath != "" {
			initialized, err := initRootPermissions(ctx, m, cfg.InitRootUserCAPath, cfg.JWT.JWTIssuer, cfg.InitContinue)
			if err != nil {
				slog.Error("Unable to initialize root permissions", err)
				os.Exit(1)
			}

			if initialized {
				slog.Info("Root auth initialized")
			}
		}

		if cfg.InitPlatformCAPath != "" {
			initialized, err := initPlatformPermissions(ctx, m, cfg.InitPlatformCAPath, cfg.JWT.JWTIssuer, cfg.InitContinue)
			if err != nil {
				slog.Error("Unable to initialize platform permissions", err)
				os.Exit(1)
			}

			if initialized {
				slog.Info("Platform auth initialized")
			}
		}

		if cfg.InitData != "" {
			initialized, err := initData(ctx, m, cfg.InitData)
			if err != nil {
				slog.Error("Unable to init provisionning data", err)
				os.Exit(1)
			}

			if initialized {
				slog.Info("Initial provisionning initialized")
			}
		}

		if !cfg.InitContinue {
			return
		}
	}

	jwtCert, jwtKey, err := cfg.JWT.JWTCertificate()
	if err != nil {
		slog.Error("Unable to get JWT certificate", err)
		os.Exit(1)
	}

	prevJWTCerts, err := cfg.JWT.JWTPreviousCertificates()
	if err != nil {
		slog.Error("Unable to get previous JWT certificates", err)
		os.Exit(1)
	}

	slog.Info("JWT info configured",
		"iss", cfg.JWT.JWTIssuer,
		"aud", cfg.JWT.JWTAudience,
		"prev", len(prevJWTCerts),
	)
	if cfg.JWT.JWTWaiveValiditySecret != "" {
		slog.Info("JWT max validity waive secret configured")
	}

	jwks := token.NewJWKS()
	if err := jwks.AppendWithPrivate(jwtCert, jwtKey); err != nil {
		slog.Error("unable to build JWKS", err)
		os.Exit(1)
	}

	for _, cert := range prevJWTCerts {
		if err := jwks.Append(cert); err != nil {
			slog.Error("Unable to append previous jwt certificate to jwks", err)
			os.Exit(1)
		}
	}

	if cfg.MTLSHeaderConf.Enabled {
		if cfg.MTLSHeaderConf.Passphrase == "" {
			slog.Error("You must pass --mtls-header-passphrase when --mtls-header-enabled is set")
			os.Exit(1)
		}
		var cipher string
		switch len(cfg.MTLSHeaderConf.Passphrase) {
		case 16:
			cipher = "AES-128"
		case 24:
			cipher = "AES-192"
		case 32:
			cipher = "AES-256"
		default:
			slog.Error("The value for --mtls-header-passphrase must be 16, 24 or 32 bytes long to select AES-128, AES-192 or AES-256")
			os.Exit(1)
		}
		slog.Info("MTLS header trust set",
			"header", cfg.MTLSHeaderConf.HeaderKey,
			"cipher", cipher,
		)
	}

	automaticEndpoint, err := bootstrap.GetPublicEndpoint(cfg.ListenAddress)
	if err != nil {
		slog.Error("Unable to get endpoint public IP", err)
		os.Exit(1)
	}

	publicAPIURL := cfg.PublicAPIURL
	if publicAPIURL == "" {
		publicAPIURL = fmt.Sprintf("https://%s", automaticEndpoint)
	}

	slog.Info("Announced public API", "url", publicAPIURL)
	cookiePolicy := http.SameSiteDefaultMode
	switch cfg.JWT.JWTCookiePolicy {
	case "strict":
		cookiePolicy = http.SameSiteStrictMode
	case "lax":
		cookiePolicy = http.SameSiteLaxMode
	case "none":
		cookiePolicy = http.SameSiteNoneMode
	}
	slog.Info("Cookie policy set", "policy", cfg.JWT.JWTCookiePolicy)

	cookieDomain := cfg.JWT.JWTCookieDomain
	if cookieDomain == "" {
		u, err := url.Parse(publicAPIURL)
		if err != nil {
			slog.Error("Unable to parse publicAPIURL", err)
			os.Exit(1)
		}
		cookieDomain = u.Hostname()
	}
	slog.Info("Cookie domain set", "domain", cookieDomain)

	trustedIssuers, err := cfg.JWT.TrustedIssuers()
	if err != nil {
		slog.Error("Unable to build trusted issuers list", err)
		os.Exit(1)
	}
	if len(trustedIssuers) > 0 {
		slog.Info("Trusted issuers set",
			"issuers",
			func() []string {
				out := make([]string, len(trustedIssuers))
				for i, o := range trustedIssuers {
					out[i] = o.URL
				}
				return out
			}(),
		)
	}

	if cfg.NATSURL == "" {
		nserver, err := bootstrap.MakeNATSServer(&cfg.NATSPublisherConf.NATSConf)
		if err != nil {
			slog.Error("Unable to make nats server", err)
			os.Exit(1)
		}
		nserver.Start()
		slog.Info("NATS server started", "url", cfg.NATSURL)
	}

	pubsub := bootstrap.MakeNATSClient(cfg.NATSConf)
	defer pubsub.Disconnect() // nolint: errcheck

	pauthn := authenticator.New(
		jwks,
		cfg.JWT.JWTIssuer,
		cfg.JWT.JWTAudience,
		authenticator.OptionIgnoredResources(publicResources...),
		authenticator.OptionExternalTrustedIssuers(trustedIssuers...),
	)
	retriever := permissions.NewRetriever(m)
	pauthz := authorizer.New(
		ctx,
		retriever,
		pubsub,
		authorizer.OptionIgnoredResources(publicResources...),
	)

	opts := append(
		bootstrap.ConfigureBahamut(
			ctx,
			cfg,
			pubsub,
			api.Manager(),
			nil,
			[]bahamut.RequestAuthenticator{pauthn},
			[]bahamut.SessionAuthenticator{pauthn},
			[]bahamut.Authorizer{pauthz},
		),
		bahamut.OptPushDispatchHandler(push.NewDispatcher(pauthz)),
		bahamut.OptPushPublishHandler(bootstrap.MakePublishHandler(pushExcludedResources)),
		bahamut.OptMTLS(nil, tls.RequestClientCert),
		bahamut.OptErrorTransformer(errorTransformer),
		bahamut.OptIdentifiableRetriever(bootstrap.MakeIdentifiableRetriever(m, api.Manager())),
	)

	if cfg.GWTopic != "" {

		gwAnnouncedAddress := cfg.GWAnnouncedAddress
		if gwAnnouncedAddress == "" {
			gwAnnouncedAddress = automaticEndpoint
		}

		opts = append(
			opts,
			bootstrap.MakeBahamutGatewayNotifier(
				ctx,
				pubsub,
				"a3s",
				cfg.GWTopic,
				gwAnnouncedAddress,
				gwpush.OptionNotifierPrefix(cfg.GWAnnouncePrefix),
				gwpush.OptionNotifierPrivateAPIOverrides(cfg.GWPrivateOverrides()),
				gwpush.OptionNotifierHiddenAPIs(cfg.GWHiddenAPIs()),
			)...,
		)

		slog.Info(
			"Gateway announcement configured",
			"address", gwAnnouncedAddress,
			"topic", cfg.GWTopic,
			"prefix", cfg.GWAnnouncePrefix,
			"overrides", cfg.GWOverridePrivate,
			"hidden", cfg.GWAPIsHidden,
		)
	}

	if len(cfg.AuditedIdentities) != 0 {

		trackedIdentities := make([]*auditor.TrackedIdentity, 0, len(cfg.AuditedIdentities))

		for _, auditedIdentity := range cfg.AuditedIdentities {

			identity := api.Manager().IdentityFromAny(auditedIdentity)

			if identity.IsEmpty() {
				slog.Error("Unknown identity found", "identity", auditedIdentity)
				os.Exit(1)
			}

			trackedIdentities = append(trackedIdentities, &auditor.TrackedIdentity{
				Identity: identity,
				Operations: []elemental.Operation{
					elemental.OperationCreate,
					elemental.OperationUpdate,
					elemental.OperationDelete,
				},
			})
		}

		opts = append(
			opts,
			bahamut.OptAuditer(auditor.NewAuditor(
				api.Manager(),
				pubsub,
				auditor.OptionTrackedIdentities(trackedIdentities...),
			)),
		)

		slog.Info(
			"Auditor configured",
			"identities", cfg.AuditedIdentities,
		)
	}

	privateAPIURL := cfg.APIServerConf.PrivateAPIURL
	if privateAPIURL == "" {
		privateAPIURL = publicAPIURL
	}

	bmanipMaker := bearermanip.Configure(
		ctx,
		privateAPIURL,
		&tls.Config{
			InsecureSkipVerify: true,
		},
	)

	server := bahamut.New(opts...)

	if err := server.RegisterCustomRouteHandler("/.well-known/jwks.json", makeJWKSHandler(jwks)); err != nil {
		slog.Error("Unable to install jwks handler", err)
		os.Exit(1)
	}

	if err := server.RegisterCustomRouteHandler("/ui/login.html", makeUILoginHandler(publicAPIURL)); err != nil {
		slog.Error("Unable to install UI login handler", err)
		os.Exit(1)
	}

	// Reusing `makeUILoginHandler` since we are serving the same html file. The UI will render the content based on the URL.
	if err := server.RegisterCustomRouteHandler("/ui/request.html", makeUILoginHandler(publicAPIURL)); err != nil {
		slog.Error("Unable to install UI request handler", err)
		os.Exit(1)
	}

	var binaryModifier *binary.Modifier
	if cfg.BinaryModifier != "" {

		if binaryModifier, err = binary.New(cfg.BinaryModifier, cfg.BinaryModifierHash, cfg.MongoConf); err != nil {
			slog.Error("unable to initialize binary modifier", err)
			os.Exit(1)
		}

		if err := binaryModifier.Run(ctx); err != nil {
			slog.Error("unable to start binary modifier", err)
			os.Exit(1)
		}

		slog.Info("Binary modifier started", "path", cfg.BinaryModifier)
	}

	var pluginModifier plugin.Modifier

	if cfg.PluginModifier != "" {
		p, err := goplugin.Open(cfg.PluginModifier)
		if err != nil {
			slog.Error("Unable to load plugin",
				"plugin", cfg.PluginModifier,
				err,
			)
			os.Exit(1)
		}
		pmaker, err := p.Lookup("MakePlugin")
		if err != nil {
			slog.Error("Unable to find 'MakePlugin' symbol in plugin",
				"plugin", cfg.PluginModifier,
				err,
			)
			os.Exit(1)
		}

		pfunc, ok := pmaker.(func() plugin.Modifier)
		if !ok {
			slog.Error("Symbol 'MakePlugin' is not a plugin.Maker",
				"plugin", cfg.PluginModifier,
				"type", fmt.Sprintf("%T", pfunc),
			)
			os.Exit(1)
		}

		pluginModifier = pfunc()

		slog.Info("Plugin modifier loaded", "path", cfg.PluginModifier)
	}

	if len(cfg.JWT.JWTForbiddenOpaqueKeys) > 0 {
		slog.Info("Forbidden opaque keys", "keys", cfg.JWT.JWTForbiddenOpaqueKeys)
	}

	bahamut.RegisterProcessorOrDie(server,
		processors.NewIssueProcessor(
			m,
			jwks,
			cfg.JWT.JWTDefaultValidity,
			cfg.JWT.JWTMaxValidity,
			cfg.JWT.JWTIssuer,
			cfg.JWT.JWTAudience,
			cfg.JWT.JWTForbiddenOpaqueKeys,
			cfg.JWT.JWTWaiveValiditySecret,
			cookiePolicy,
			cookieDomain,
			cfg.MTLSHeaderConf.Enabled,
			cfg.MTLSHeaderConf.HeaderKey,
			cfg.MTLSHeaderConf.Passphrase,
			pluginModifier,
			binaryModifier,
		),
		api.IssueIdentity,
	)
	bahamut.RegisterProcessorOrDie(server, processors.NewMTLSSourcesProcessor(m), api.MTLSSourceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewLDAPSourcesProcessor(m), api.LDAPSourceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewOIDCSourcesProcessor(m), api.OIDCSourceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewSAMLSourcesProcessor(m), api.SAMLSourceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewHTTPSourcesProcessor(m), api.HTTPSourceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewA3SSourcesProcessor(m), api.A3SSourceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewOAuth2SourcesProcessor(m), api.OAuth2SourceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewPermissionsProcessor(retriever), api.PermissionsIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewAuthzProcessor(pauthz, jwks, cfg.JWT.JWTIssuer, cfg.JWT.JWTAudience), api.AuthzIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewNamespacesProcessor(m, pubsub), api.NamespaceIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewNamespaceDeletionRecordsProcessor(m), api.NamespaceDeletionRecordIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewAuthorizationProcessor(m, pubsub, retriever, cfg.JWT.JWTIssuer), api.AuthorizationIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewImportProcessor(bmanipMaker, pauthz), api.ImportIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewRevocationsProcessor(m, pubsub), api.RevocationIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewGroupProcessor(m, pubsub), api.GroupIdentity)
	bahamut.RegisterProcessorOrDie(server, processors.NewLogoutProcessor(m, pubsub, cookiePolicy, cookieDomain), api.LogoutIdentity)

	// Object clean up
	notification.Subscribe(
		ctx,
		pubsub,
		nscache.NotificationNamespaceChanges,
		notification.MakeNamespaceCleaner(
			ctx,
			m,
			api.Manager(),
			api.NamespaceDeletionRecordIdentity,
		),
	)
	go jobs.ScheduleOrphanedObjectsDeleteJob(
		ctx,
		m, m,
		api.AllIdentities(),
		1*time.Minute,
	)

	server.Run(ctx)
}

func createMongoDBAccount(cfg conf.MongoConf, username string) error {

	m := bootstrap.MakeMongoManipulator(cfg, &hasher.Hasher{}, api.Manager())

	db, closeFunc, _ := manipmongo.GetDatabase(m)
	defer closeFunc()

	user := mgo.User{
		Username: username,
		OtherDBRoles: map[string][]mgo.Role{
			"a3s": {mgo.RoleReadWrite, mgo.RoleDBAdmin},
		},
	}

	if err := db.UpsertUser(&user); err != nil {
		return fmt.Errorf("unable to upsert the user: %w", err)
	}

	slog.Info("Successfully created mongodb account", "user", username)

	return nil
}

func errorTransformer(err error) error {

	switch {
	case errors.As(err, &manipulate.ErrObjectNotFound{}):
		return elemental.NewError("Not Found", err.Error(), "a3s", http.StatusNotFound)

	case errors.As(err, &manipulate.ErrConstraintViolation{}):
		return elemental.NewError("Constraint Violation", err.Error(), "a3s", http.StatusUnprocessableEntity)

	case errors.As(err, &manipulate.ErrCannotCommunicate{}):
		return elemental.NewError("Communication Error", err.Error(), "a3s", http.StatusServiceUnavailable)

	case errors.As(err, &manipulate.ErrDisconnected{}), errors.Is(err, context.Canceled):
		return elemental.NewError("Client Disconnected", err.Error(), "a3s", http.StatusNotAcceptable)
	}

	for ierr := errors.Unwrap(err); ierr != nil; ierr = errors.Unwrap(ierr) {
		if e, ok := ierr.(elemental.Error); ok {
			e.Description = strings.SplitN(err.Error(), e.Error(), 2)[0] + e.Description
			err = e
			break
		}

		if e, ok := ierr.(elemental.Errors); ok {
			e[0].Description = strings.SplitN(err.Error(), e[0].Error(), 2)[0] + e[0].Description
			err = e
			break
		}
	}

	return err
}

func createRootNamespaceIfNeeded(m manipulate.Manipulator) error {

	mctx := manipulate.NewContext(context.Background(),
		manipulate.ContextOptionFilter(
			elemental.NewFilterComposer().
				WithKey("name").Equals("/").
				Done(),
		),
	)

	c, err := m.Count(mctx, api.NamespaceIdentity)
	if err != nil {
		return fmt.Errorf("unable to check if root namespace exists: %w", err)
	}

	if c == 1 {
		return nil
	}

	if c > 1 {
		panic("more than one namespace / found")
	}

	ns := api.NewNamespace()
	ns.Name = "/"
	ns.Namespace = "root"

	if err := m.Create(nil, ns); err != nil {
		return fmt.Errorf("unable to create root namespace: %w", err)
	}

	return nil
}

func initRootPermissions(ctx context.Context, m manipulate.Manipulator, caPath string, issuer string, ifNeeded bool) (bool, error) {

	caData, err := os.ReadFile(caPath)
	if err != nil {
		return false, fmt.Errorf("unable to read root user ca: %w", err)
	}

	caCerts, err := tglib.ParseCertificates(caData)
	if err != nil {
		return false, fmt.Errorf("unable to parse root user ca: %w", err)
	}

	chain := make([]string, len(caCerts))
	for i, cert := range caCerts {
		chain[i] = token.Fingerprint(cert)
	}

	source := api.NewMTLSSource()
	source.Namespace = "/"
	source.Name = "root"
	source.Description = "Auth source to authenticate root users"
	source.CA = string(caData)
	source.CreateTime = time.Now()
	source.UpdateTime = source.CreateTime
	certs, err := tglib.ParseCertificates([]byte(source.CA))
	if err != nil {
		return false, err
	}
	source.Fingerprints = make([]string, len(certs))
	source.SubjectKeyIDs = make([]string, len(certs))
	for i, cert := range certs {
		source.Fingerprints[i] = token.Fingerprint(cert)
		source.SubjectKeyIDs[i] = fmt.Sprintf("%02X", cert.SubjectKeyId)
	}
	if err := m.Create(manipulate.NewContext(ctx), source); err != nil {
		if errors.As(err, &manipulate.ErrConstraintViolation{}) && ifNeeded {
			return false, nil
		}
		return false, fmt.Errorf("unable to create root mtls auth source: %w", err)
	}

	auth := api.NewAuthorization()
	auth.Namespace = "/"
	auth.Name = "root-mtls-authorization"
	auth.Description = "Authorization to allow root users"
	auth.TrustedIssuers = []string{issuer}
	auth.Subject = [][]string{
		{
			"@source:type=mtls",
			"@source:name=root",
			"@source:namespace=/",
			fmt.Sprintf("issuerchain=%s", strings.Join(chain, ",")),
		},
	}
	auth.FlattenedSubject = auth.Subject[0]
	auth.Permissions = []string{"*:*"}
	auth.TargetNamespaces = []string{"/"}
	auth.Hidden = true
	auth.CreateTime = time.Now()
	auth.UpdateTime = auth.CreateTime

	if err := m.Create(manipulate.NewContext(ctx), auth); err != nil {
		return false, fmt.Errorf("unable to create root auth: %w", err)
	}

	return true, nil
}

func initPlatformPermissions(ctx context.Context, m manipulate.Manipulator, caPath string, issuer string, ifNeeded bool) (bool, error) {

	caData, err := os.ReadFile(caPath)
	if err != nil {
		return false, fmt.Errorf("unable to read platform ca: %w", err)
	}

	caCerts, err := tglib.ParseCertificates(caData)
	if err != nil {
		return false, fmt.Errorf("unable to parse platform ca: %w", err)
	}

	chain := make([]string, len(caCerts))
	for i, cert := range caCerts {
		chain[i] = token.Fingerprint(cert)
	}

	source := api.NewMTLSSource()
	source.Namespace = "/"
	source.Name = "platform"
	source.Description = "Auth source used to authenticate internal platform services"
	source.CA = string(caData)
	source.CreateTime = time.Now()
	source.UpdateTime = source.CreateTime
	certs, err := tglib.ParseCertificates([]byte(source.CA))
	if err != nil {
		return false, err
	}
	source.Fingerprints = make([]string, len(certs))
	source.SubjectKeyIDs = make([]string, len(certs))
	for i, cert := range certs {
		source.Fingerprints[i] = token.Fingerprint(cert)
		source.SubjectKeyIDs[i] = fmt.Sprintf("%02X", cert.SubjectKeyId)
	}

	if err := m.Create(manipulate.NewContext(ctx), source); err != nil {
		if errors.As(err, &manipulate.ErrConstraintViolation{}) && ifNeeded {
			return false, nil
		}
		return false, fmt.Errorf("unable to create platform mtls auth source: %w", err)
	}

	auth := api.NewAuthorization()
	auth.Namespace = "/"
	auth.Name = "platform-mtls-authorization"
	auth.Description = "Authorization to allow internal services"
	auth.TrustedIssuers = []string{issuer}
	auth.Subject = [][]string{
		{
			"@source:type=mtls",
			"@source:name=platform",
			"@source:namespace=/",
			fmt.Sprintf("issuerchain=%s", strings.Join(chain, ",")),
		},
	}
	auth.FlattenedSubject = auth.Subject[0]
	auth.Permissions = []string{"*:*"}
	auth.TargetNamespaces = []string{"/"}
	auth.Hidden = true
	auth.CreateTime = time.Now()
	auth.UpdateTime = auth.CreateTime

	if err := m.Create(manipulate.NewContext(ctx), auth); err != nil {
		return false, fmt.Errorf("unable to create root auth: %w", err)
	}

	return true, nil
}

func initData(ctx context.Context, m manipulate.Manipulator, dataPath string) (bool, error) {

	data, err := os.ReadFile(dataPath)
	if err != nil {
		return false, fmt.Errorf("unable to read init import file: %w", err)
	}

	importFile := api.NewImport()
	if err := yaml.Unmarshal(data, importFile); err != nil {
		return false, fmt.Errorf("unable to unmarshal import file: %w", err)
	}

	values := []elemental.Identifiables{
		importFile.LDAPSources,
		importFile.OIDCSources,
		importFile.A3SSources,
		importFile.MTLSSources,
		importFile.HTTPSources,
		importFile.Authorizations,
	}

	for _, lst := range values {
		for i, o := range lst.List() {
			if o.(elemental.Namespaceable).GetNamespace() == "" {
				return false, fmt.Errorf(
					"missing namespace property for object '%s' at index %d",
					lst.Identity().Name,
					i,
				)
			}
		}
	}

	for _, lst := range values {

		if len(lst.List()) == 0 {
			continue
		}

		if err := importing.Import(
			ctx,
			api.Manager(),
			m,
			"/",
			"a3s:init:data",
			lst,
			false,
		); err != nil {
			return false, fmt.Errorf("unable to import '%s': %w", lst.Identity().Name, err)
		}
	}

	return true, nil
}

func makeJWKSHandler(jwks *token.JWKS) http.HandlerFunc {

	return func(w http.ResponseWriter, req *http.Request) {

		jwks.RLock()
		defer jwks.RUnlock()

		data, err := elemental.Encode(elemental.EncodingTypeJSON, jwks)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}

func makeUILoginHandler(api string) http.HandlerFunc {

	return func(w http.ResponseWriter, req *http.Request) {

		q := req.URL.Query()

		redirect := q.Get("redirect")
		audience := q.Get("audience")

		if proxy := q.Get("proxy"); proxy != "" {
			api = proxy
		}

		data, err := ui.GetLogin(api, redirect, audience)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "text/html")
		_, _ = w.Write(data)
	}
}
