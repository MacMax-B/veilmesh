// Package releaseinfo contains build metadata injected into release binaries.
package releaseinfo

import "strings"

var (
	Version = "dev"
	Commit  = "unknown"
)

// String returns a stable, non-empty release identifier. Release builds inject
// both fields with -ldflags; local builds deliberately identify as development.
func String() string {
	version := strings.TrimSpace(Version)
	if version == "" {
		version = "dev"
	}
	commit := strings.TrimSpace(Commit)
	if commit == "" || commit == "unknown" {
		return version
	}
	return version + " (" + commit + ")"
}
