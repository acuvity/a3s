package bearermanip

import (
	"context"
	"crypto/tls"

	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniphttp"
)

// MakerFunc is a functon you can use to create a bearer manipulator.
type MakerFunc func(bahamut.Context) manipulate.Manipulator

// Configure returns a function that can be used to create bearer manipulators that will act on
// behalf of the calling user.
func Configure(ctx context.Context, api string, tlsConfig *tls.Config, options ...maniphttp.Option) MakerFunc {

	return func(bctx bahamut.Context) manipulate.Manipulator {

		opts := append(
			[]maniphttp.Option{
				maniphttp.OptionDisableCompression(),
				maniphttp.OptionToken(token.FromRequest(bctx.Request())),
				maniphttp.OptionNamespace(bctx.Request().Namespace),
			},
			options...,
		)

		// Always add back given tls config after everything else.
		opts = append(opts, maniphttp.OptionTLSConfig(tlsConfig))

		m, _ := maniphttp.New(ctx, api, opts...)

		return m
	}
}
