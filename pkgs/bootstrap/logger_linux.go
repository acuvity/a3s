//go:build linux

package bootstrap

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

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
