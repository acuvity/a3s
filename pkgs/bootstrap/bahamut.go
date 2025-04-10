package bootstrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/fatih/structs"
	"github.com/opentracing/opentracing-go"
	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/bahamut/authorizer/simple"
	"go.acuvity.ai/bahamut/gateway/upstreamer/push"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
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
	}

	cs := structs.New(cfg)

	_, okStaticTLS := cs.FieldOk(structs.Name(conf.TLSConf{}))
	_, okAutoTLS := cs.FieldOk(structs.Name(conf.TLSAutoConf{}))

	var staticConf conf.TLSConf
	var autoConf conf.TLSAutoConf

	if okStaticTLS {
		if f, ok := cs.FieldOk(structs.Name(conf.TLSConf{})); ok {
			staticConf = f.Value().(conf.TLSConf)
		}
	}

	if okAutoTLS {
		if f, ok := cs.FieldOk(structs.Name(conf.TLSAutoConf{})); ok {
			autoConf = f.Value().(conf.TLSAutoConf)
		}
	}

	tlscfg, err := TLSConfig(autoConf, staticConf)
	if err != nil {
		slog.Error("Unable to configure tls", err)
		os.Exit(1)
	}

	if tlscfg != nil {
		opts = append(opts,
			bahamut.OptTLS(tlscfg.Certificates, nil),
			bahamut.OptTLSNextProtos([]string{"h2", "http/1.1"}), // enable http2 support.
		)

		if clientCA := tlscfg.ClientCAs; clientCA != nil {
			opts = append(opts, bahamut.OptMTLS(clientCA, tls.RequireAndVerifyClientCert))
		}

	}

	if f, ok := cs.FieldOk(structs.Name(conf.APIServerConf{})); ok {
		c := f.Value().(conf.APIServerConf)

		slog.Info("Max TCP connections", "max", c.MaxConnections)
		opts = append(
			opts,
			bahamut.OptRestServer(c.ListenAddress),
			bahamut.OptMaxConnection(c.MaxConnections),
		)

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

// GetPublicEndpoint will get the general endpoint based
// on the listen address. It will get the port,
// then use system construct to get the public IP
// and append the port.
func GetPublicEndpoint(listenAddress string) (string, error) {

	_, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return "", fmt.Errorf("unable to parse listen address: %w", err)
	}

	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve hostname: %w", err)
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("unable to resolve hostname: %w", err)
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("unable to find any IP in resolved hostname: %w", err)
	}

	var endpoint string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if len(ip.To4()) == net.IPv4len {
			endpoint = addr
			break
		}
	}

	if endpoint == "" {
		endpoint = addrs[0]
	}

	return fmt.Sprintf("%s:%s", endpoint, port), nil
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
