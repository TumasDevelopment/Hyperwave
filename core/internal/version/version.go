// Package version contiene la versione, impostata in compilazione da deploy/build.sh.
package version

// Version è sostituita con -ldflags "-X hyperwave/internal/version.Version=...".
var Version = "dev"
