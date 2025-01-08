package version

import (
	"fmt"
	"log/slog"
	"runtime"
)

// Various git information set at build
var (
	GitSha    = "n/a"
	GitTag    = "n/a"
	GitBranch = "n/a"
	BuildDate = "n/a"
)

// String return the version string.
func String(name string) string {
	if GitTag == "" {
		GitTag = "dev"
	}
	return fmt.Sprintf(
		"%s\n\ntag:\t%s\nsha:\t%s\nbranch:\t%s\ndate:\t%s\ngo:\t%s\nos:\t%s\narch:\t%s",
		name,
		GitTag,
		GitSha,
		GitBranch,
		BuildDate,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)
}

// Log logs the version information.
func Log(name string) {
	if GitTag == "" {
		GitTag = "dev"
	}
	slog.Info("Version", "name", name, "tag", GitTag, "branch", GitBranch, "sha", GitSha)
}

// Short returns the short version string.
func Short() string {
	return fmt.Sprintf(
		"%s %s (%s/%s)",
		GitTag,
		GitSha,
		runtime.GOOS,
		runtime.GOARCH,
	)
}
