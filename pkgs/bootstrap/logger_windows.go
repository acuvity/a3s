//go:build windows

package bootstrap

import (
	"log/slog"
)

func handleElevationSignal(_ string, _ string, _ string) {

	slog.Info("Log level elevation from signals is not supported on windows")
}
