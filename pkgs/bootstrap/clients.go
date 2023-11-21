package bootstrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.acuvity.ai/a3s/pkgs/authenticator"
	"go.acuvity.ai/a3s/pkgs/authlib"
	"go.acuvity.ai/a3s/pkgs/authorizer"
	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/sharder"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniphttp"
	"go.acuvity.ai/manipulate/manipmongo"
	"go.acuvity.ai/tg/tglib"
)

// MakeNATSClient returns a connected pubsub server client.
// This function is not meant to be used outside of the platform. It will fatal
// anytime it feels like it.
func MakeNATSClient(cfg conf.NATSConf) bahamut.PubSubClient {

	opts := []bahamut.NATSOption{
		bahamut.NATSOptClientID(cfg.NATSClientID),
		bahamut.NATSOptClusterID(cfg.NATSClusterID),
		bahamut.NATSOptCredentials(cfg.NATSUser, cfg.NATSPassword),
	}

	tlscfg, err := cfg.TLSConfig()
	if err != nil {
		slog.Error("Unable to prepare TLS config for nats", err)
		os.Exit(1)
	}

	if tlscfg != nil {
		opts = append(opts, bahamut.NATSOptTLS(tlscfg))
	}

	pubsub := bahamut.NewNATSPubSubClient(cfg.NATSURL, opts...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := pubsub.Connect(ctx); err != nil {
		slog.Error("Could not connect to nats", err)
		os.Exit(1)
	}

	slog.Info("Connected to nats", "server", cfg.NATSURL)

	return pubsub
}

// MakeMongoManipulator returns a configured mongo manipulator.
// This function is not meant to be used outside of the platform. It will fatal
// anytime it feels like it.
func MakeMongoManipulator(cfg conf.MongoConf, hasher sharder.Hasher, model elemental.ModelManager, additionalOptions ...manipmongo.Option) manipulate.TransactionalManipulator {

	var consistency manipulate.ReadConsistency
	switch cfg.MongoConsistency {
	case "strong":
		consistency = manipulate.ReadConsistencyStrong
	case "monotonic":
		consistency = manipulate.ReadConsistencyMonotonic
	case "eventual":
		consistency = manipulate.ReadConsistencyEventual
	case "nearest":
		consistency = manipulate.ReadConsistencyNearest
	case "weakest":
		consistency = manipulate.ReadConsistencyWeakest
	default:
		panic(fmt.Sprintf("unknown consistency '%s'", cfg.MongoConsistency))
	}

	opts := append(
		[]manipmongo.Option{
			manipmongo.OptionCredentials(cfg.MongoUser, cfg.MongoPassword, cfg.MongoAuthDB),
			manipmongo.OptionConnectionPoolLimit(cfg.MongoPoolSize),
			manipmongo.OptionDefaultReadConsistencyMode(consistency),
			manipmongo.OptionTranslateKeysFromModelManager(model),
			manipmongo.OptionDefaultRetryFunc(func(i manipulate.RetryInfo) error {
				info := i.(manipmongo.RetryInfo)
				slog.Debug("mongo manipulator retry",
					"try", info.Try(),
					"operation", string(info.Operation),
					"identity", info.Identity.Name,
					info.Err(),
				)
				return nil
			}),
		},
		additionalOptions...,
	)

	if hasher != nil {
		opts = append(
			opts,
			manipmongo.OptionSharder(sharder.New(hasher)),
		)
	}

	tlscfg, err := cfg.TLSConfig()
	if err != nil {
		slog.Error("Unable to prepare TLS config for mongodb", err)
		os.Exit(1)
	}

	if tlscfg != nil {
		opts = append(opts, manipmongo.OptionTLS(tlscfg))
	}

	if cfg.MongoAttrEncryptKey != "" {
		encrypter, err := elemental.NewAESAttributeEncrypter(cfg.MongoAttrEncryptKey)
		if err != nil {
			slog.Error("Unable to create mongodb attribute encrypter", err)
			os.Exit(1)
		}
		opts = append(opts, manipmongo.OptionAttributeEncrypter(encrypter))
		slog.Info("Attribute encryption", "status", "enabled")
	} else {
		slog.Warn("Attribute encryption", "status", "disabled")
	}

	m, err := manipmongo.New(cfg.MongoURL, cfg.MongoDBName, opts...)
	if err != nil {
		slog.Error("Unable to connect to mongo", err)
		os.Exit(1)
	}

	slog.Info("Connected to mongodb", "url", cfg.MongoURL, "db", cfg.MongoDBName)

	return m
}

// MakeA3SManipulator returns an HTTP manipulator for a3s communication.
func MakeA3SManipulator(ctx context.Context, a3sConfig conf.A3SClientConf) (manipulate.Manipulator, error) {

	cert, key, err := tglib.ReadCertificatePEM(
		a3sConfig.A3SClientCert,
		a3sConfig.A3SClientKey,
		a3sConfig.A3SClientKeyPass,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read certificate %w", err)
	}

	clientCert, err := tglib.ToTLSCertificate(cert, key)
	if err != nil {
		return nil, fmt.Errorf("unable to convert client certificate: %w", err)
	}

	systemCAPool, err := a3sConfig.SystemCAPool()
	if err != nil {
		return nil, fmt.Errorf("unable to get systemCAPool: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:      systemCAPool,
		Certificates: []tls.Certificate{clientCert},
	}

	m, err := maniphttp.New(
		ctx,
		a3sConfig.A3SURL,
		maniphttp.OptionNamespace(a3sConfig.A3SNamespace),
		maniphttp.OptionTokenManager(
			authlib.NewX509TokenManager(
				a3sConfig.A3SNamespace,
				a3sConfig.A3SourceName,
			),
		),
		maniphttp.OptionTLSConfig(tlsConfig),
		maniphttp.OptionDefaultRetryFunc(func(i manipulate.RetryInfo) error {
			info := i.(maniphttp.RetryInfo)
			slog.Debug("a3s manipulator retry",
				"try", info.Try(),
				"method", info.Method,
				"url", info.URL,
				info.Err(),
			)
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to create http manipulator: namespace=%s, source=%s :%w",
			a3sConfig.A3SNamespace,
			a3sConfig.A3SourceName,
			err,
		)
	}

	return m, nil
}

// MakeA3SRemoteAuth is a convenience function that will return
// ready to user Authenticator and Authorizers for a bahamut server.
// It uses the given manipulator to talk to the instance of a3s.
func MakeA3SRemoteAuth(
	ctx context.Context,
	m manipulate.Manipulator,
	requiredIssuer string,
	requiredAudience string,
) (*authenticator.Authenticator, authorizer.Authorizer, error) {

	jwks, err := token.NewRemoteJWKS(
		ctx,
		maniphttp.ExtractClient(m),
		fmt.Sprintf("%s/.well-known/jwks.json", maniphttp.ExtractEndpoint(m)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to retrieve a3s JWT: %w", err)
	}

	return authenticator.New(
			jwks,
			requiredIssuer,
			requiredAudience,
		),
		authorizer.NewRemote(
			ctx,
			m,
			permissions.NewRemoteRetriever(m),
		),
		nil
}
