package bootstrap

import (
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"go.acuvity.ai/a3s/pkgs/conf"
)

var loggerConfigured bool

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

	if loggerConfigured {
		panic("configureLogger called multiple times - this should only be called once during application initialization")
	}

	loggerConfigured = true

	setLoggerHandler(name, level, format)
	go handleElevationSignal(name, level, format)
}

// setLoggerHandler configures the slog handler without starting a new signal handler.
// This is called both during initial setup and when toggling log levels.
func setLoggerHandler(name string, level string, format string) {

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
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level:       lvl,
			ReplaceAttr: errReplacer,
		})
	case "console":
		handler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:       lvl,
			ReplaceAttr: errReplacer,
			TimeFormat:  time.Stamp,
		})
	case "silent":
		handler = slog.NewTextHandler(io.Discard, nil)
	default:
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level:       lvl,
			ReplaceAttr: errReplacer,
		})
	}

	logger := slog.New(handler)

	if name != "" && format != "console" {
		logger = logger.With("srv", name)
	}

	slog.SetDefault(logger)
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
