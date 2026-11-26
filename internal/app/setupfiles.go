package app

import (
	"github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"
)

// The credential files of basalt init --remote and basalt service install
// (internal/setup/out/credfiles), forwarded to the CLI, which may not import
// an adapter.

// trustedDir is a directory opened without following a link
// (credfiles.TrustedDir).
type trustedDir = credfiles.TrustedDir

// pathCredFiles reaches the credential files by path (credfiles.PathCredFiles).
type pathCredFiles = credfiles.PathCredFiles
