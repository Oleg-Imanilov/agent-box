// Package version holds build-time version information shared by all binaries.
package version

// Version is overridden at build time via -ldflags "-X .../internal/version.Version=...".
var Version = "0.0.0-dev"

// String returns a human-readable version string for the named component.
func String(component string) string {
	return component + " " + Version
}
