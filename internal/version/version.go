// Package version carries the build-time stamped version string.
package version

// Version is stamped by the Makefile / goreleaser via ldflags; "dev" otherwise.
var Version = "dev"
