package bootstrap

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/fatih/structs"
	"github.com/opentracing/opentracing-go"
	"go.aporeto.io/a3s/pkgs/conf"
	"go.aporeto.io/bahamut"
	"go.aporeto.io/bahamut/authorizer/simple"
	"go.aporeto.io/bahamut/gateway/upstreamer/push"
	"go.aporeto.io/elemental"
	"go.aporeto.io/manipulate"
)

// ConfigureBahamut returns a list of bahamut.Option based on provided configuration.
func ConfigureBahamut(
	ctx context.Context,
	cfg any,
	pubsub bahamut.PubSubClient,
	apiManager elemental.ModelManager,
	healthHandler bahamut.HealthServerFunc,
	requestAuthenticators []bahamut.RequestAuthenticator,
	sessionAuthenticators []bahamut.SessionAuthenticator,
	authorizers []bahamut.Authorizer,
) (opts []bahamut.Option) {

	modelManagers := map[int]elemental.ModelManager{0: apiManager, 1: apiManager}

	l := slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)

	// Default options.
	opts = []bahamut.Option{
		// bahamut.OptServiceInfo(serviceName, serviceVersion, subversions),
		bahamut.OptModel(modelManagers),
		bahamut.OptAuthenticators(requestAuthenticators, sessionAuthenticators),
		bahamut.OptAuthorizers(authorizers),
		bahamut.OptOpentracingTracer(opentracing.GlobalTracer()),
		bahamut.OptDisableCompression(),
		bahamut.OptHTTPLogger(l),
		bahamut.OptErrorTransformer(ErrorTransformer),
	}

	cs := structs.New(cfg)

	if f, ok := cs.FieldOk(structs.Name(conf.APIServerConf{})); ok {
		c := f.Value().(conf.APIServerConf)
		opts = append(
			opts,
			bahamut.OptRestServer(c.ListenAddress),
			bahamut.OptMaxConnection(c.MaxConnections),
		)

		slog.Info("Max TCP connections", "max", c.MaxConnections)

		tlscfg, err := c.TLSConfig()
		if err != nil {
			slog.Error("Unable to configure tls", err)
			os.Exit(1)
		}

		if tlscfg != nil {

			opts = append(opts,
				bahamut.OptTLS(tlscfg.Certificates, nil),
				bahamut.OptTLSNextProtos([]string{"h2"}), // enable http2 support.
			)

			if clientCA := tlscfg.ClientCAs; clientCA != nil {
				opts = append(opts, bahamut.OptMTLS(clientCA, tls.RequireAndVerifyClientCert))
			}
		}

		if c.CORSDefaultOrigin != "" || len(c.CORSAdditionalOrigins) > 0 {
			opts = append(
				opts,
				bahamut.OptCORSAccessControl(
					bahamut.NewDefaultCORSController(
						c.CORSDefaultOrigin,
						c.CORSAdditionalOrigins,
					),
				),
			)
			slog.Info("CORS origin configured",
				"default", c.CORSDefaultOrigin,
				"additional", c.CORSAdditionalOrigins,
			)
		}
	}

	if f, ok := cs.FieldOk(structs.Name(conf.HealthConfiguration{})); ok {
		c := f.Value().(conf.HealthConfiguration)
		if c.EnableHealth {
			opts = append(
				opts,
				bahamut.OptHealthServer(c.HealthListenAddress, healthHandler),
				bahamut.OptHealthServerMetricsManager(bahamut.NewPrometheusMetricsManager()),
			)
		}
	}

	if f, ok := cs.FieldOk(structs.Name(conf.ProfilingConf{})); ok {
		c := f.Value().(conf.ProfilingConf)
		if c.ProfilingEnabled {
			opts = append(opts, bahamut.OptProfilingLocal(c.ProfilingListenAddress))
		}
	}

	if f, ok := cs.FieldOk(structs.Name(conf.RateLimitingConf{})); ok {
		c := f.Value().(conf.RateLimitingConf)
		if c.RateLimitingEnabled {
			opts = append(opts, bahamut.OptRateLimiting(float64(c.RateLimitingRPS), c.RateLimitingBurst))
			slog.Info("Rate limit configured",
				"rps", c.RateLimitingRPS,
				"burst", c.RateLimitingBurst,
			)
		}
	}

	if f, ok := cs.FieldOk(structs.Name(conf.HTTPTimeoutsConf{})); ok {
		c := f.Value().(conf.HTTPTimeoutsConf)
		opts = append(opts, bahamut.OptTimeouts(c.TimeoutRead, c.TimeoutWrite, c.TimeoutIdle))

		slog.Debug("Timeouts configured",
			"read", c.TimeoutRead,
			"write", c.TimeoutWrite,
			"idle", c.TimeoutIdle,
		)
	}

	if f, ok := cs.FieldOk(structs.Name(conf.NATSPublisherConf{})); ok {
		c := f.Value().(conf.NATSPublisherConf)
		opts = append(opts,
			bahamut.OptPushServer(pubsub, c.NATSPublishTopic),
			bahamut.OptPushServerEnableSubjectHierarchies(),
		)
	}

	return opts
}

// MakeBahamutGatewayNotifier returns the bahamut options needed
// to make A3S announce itself to a bahamut gateway.
func MakeBahamutGatewayNotifier(
	ctx context.Context,
	pubsub bahamut.PubSubClient,
	serviceName string,
	gatewayTopic string,
	anouncedAddress string,
	nopts ...push.NotifierOption,
) []bahamut.Option {

	opts := []bahamut.Option{}

	if gatewayTopic == "" {
		return nil
	}

	nw := push.NewNotifier(
		pubsub,
		gatewayTopic,
		serviceName,
		anouncedAddress,
		nopts...,
	)

	opts = append(opts,
		bahamut.OptPostStartHook(nw.MakeStartHook(ctx)),
		bahamut.OptPreStopHook(nw.MakeStopHook()),
	)

	slog.Info(
		"Gateway topic set",
		"topic", gatewayTopic,
		"service", serviceName,
	)

	return opts
}

// ErrorTransformer transforms a disconnected error into an not acceptable.
// This avoid 500 errors due to clients being disconnected.
func ErrorTransformer(err error) error {

	switch {

	case errors.As(err, &manipulate.ErrDisconnected{}),
		errors.As(err, &manipulate.ErrDisconnected{}),
		errors.Is(err, context.Canceled):

		return elemental.NewError(
			"Client Disconnected",
			err.Error(),
			"a3s",
			http.StatusNotAcceptable,
		)

	case manipulate.IsObjectNotFoundError(err):

		return elemental.NewError(
			"Not Found",
			err.Error(),
			"a3s",
			http.StatusNotFound,
		)

	default:
		return nil
	}
}

// MakeIdentifiableRetriever returns a bahamut.IdentifiableRetriever to handle patches as classic update.
func MakeIdentifiableRetriever(
	manipulator manipulate.Manipulator,
	apiManager elemental.ModelManager,
) bahamut.IdentifiableRetriever {

	return func(req *elemental.Request) (elemental.Identifiable, error) {

		identity := req.Identity

		obj := apiManager.Identifiable(identity)
		obj.SetIdentifier(req.ObjectID)

		if err := manipulator.Retrieve(nil, obj); err != nil {
			return nil, err
		}

		return obj, nil
	}
}

// MakePublishHandler returns a bahamut.PushPublishHandler that publishes all events but the
// ones related to the given identities.
func MakePublishHandler(excludedIdentities []elemental.Identity) bahamut.PushPublishHandler {

	return simple.NewPublishHandler(func(event *elemental.Event) (bool, error) {
		for _, i := range excludedIdentities {
			if event.Identity == i.Name {
				return false, nil
			}
		}
		return true, nil
	})
}
