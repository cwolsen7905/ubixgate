// Package version holds the build version, set at link time by the Makefile.
package version

// Version is overwritten with -ldflags "-X .../internal/version.Version=v0.1.0".
var Version = "dev"
