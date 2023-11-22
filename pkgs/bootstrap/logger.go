package bootstrap

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lmittmann/tint"
	"go.acuvity.ai/a3s/pkgs/conf"
)

// ConfigureLogger configures the logging subsystem.
func ConfigureLogger(serviceName string, cfg conf.LoggingConf) CloseRecorderHandler {

	var err error

	configureLogger(serviceName, cfg.LogLevel, cfg.LogFormat)

	f, err := ConfigureTracerWithURL(cfg.LogTracerURL, serviceName)
	if err != nil {
		slog.Warn("Unable to configure the OpenTracing", err)
	}

	if f != nil {
		slog.Info("OpenTracing enabled", "server", cfg.LogTracerURL)
	}

	return f
}

func configureLogger(name string, level string, format string) {

	lvl := stringToLevel(level)

	errReplacer := func(groups []string, a slog.Attr) slog.Attr {
		switch e := a.Value.Any().(type) {
		case error:
			return slog.String("err", e.Error())
		default:
			return a
		}
	}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:       lvl,
			ReplaceAttr: errReplacer,
		})
	case "console":
		handler = tint.NewHandler(os.Stdout, &tint.Options{
			Level:       lvl,
			ReplaceAttr: errReplacer,
			TimeFormat:  time.Stamp,
		})
	default:
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:       lvl,
			ReplaceAttr: errReplacer,
		})
	}

	logger := slog.New(handler)

	if name != "" && format != "console" {
		logger = logger.With("srv", name)
	}

	slog.SetDefault(logger)

	go handleElevationSignal(name, level, format)
}

func stringToLevel(level string) slog.Level {

	switch level {
	case "trace", "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error", "fatal":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func handleElevationSignal(name string, level string, format string) {

	var elevated bool

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)

	for s := range c {

		if s == syscall.SIGINT {
			return
		}

		elevated = !elevated

		if elevated {
			configureLogger(name, "debug", format)
			slog.Info("Log level elevated to debug")
		} else {
			configureLogger(name, level, format)
			slog.Info("Log level restored to original configuration", "level", level)
		}
	}
}
