//go:build !unix

package config

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

// credentialRules: see nofollow_unix.go. The engine runs on linux and darwin
// only; elsewhere ownerfile checks no owner.
func credentialRules() ownerfile.Rules { return ownerfile.Rules{MaxBytes: maxConfigBytes} }
