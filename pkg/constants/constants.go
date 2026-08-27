// Package constants holds version and shared constants used by both the
// command layer and output/formatter layers, so they are never out of sync.
package constants

// Version is the single source of truth for the tool version.
// It is read by cmd/gosleek (CLI banner/help) and output/sarif.go (SARIF).
const Version = "1.0.1"
