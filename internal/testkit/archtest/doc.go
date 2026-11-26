// Package archtest enforces the architecture rules in ARCHITECTURE.md as a Go
// test: the import rules between layers, the purity of internal/core, the rule
// that only services call the core's decisions, and the core register.
//
// Known violations live in baseline/, one file per importing package. A new
// violation fails the test; so does a baseline entry that is no longer
// violated (remove it). Run `go test ./internal/testkit/archtest -update` to
// remove the lines a change fixed; it never adds a line.
package archtest
