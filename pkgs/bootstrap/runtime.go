package bootstrap

import (
	"log/slog"
	"os"
	"runtime"

	"go.uber.org/automaxprocs/maxprocs"
)

// ConfigureMaxProc configures the program's GOMAXPROCS to the given
// value if not 0. If 0, the default GOMAXPROCS will be used.
func ConfigureMaxProc(overrideMax int) {

	if overrideMax == 0 {
		if _, err := maxprocs.Set(maxprocs.Logger(func(msg string, args ...any) {})); err != nil {
			slog.Error("Unable to set automaxprocs", err)
			os.Exit(1)
		}
	} else {
		runtime.GOMAXPROCS(overrideMax)
	}

	slog.Info("GOMAXPROCS configured", "max", runtime.GOMAXPROCS(0))
}
