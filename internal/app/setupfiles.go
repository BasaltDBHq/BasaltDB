package app

import (
	"os"

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

// maxCredentialBytes bounds a credential (credfiles.MaxCredentialBytes).
const maxCredentialBytes = credfiles.MaxCredentialBytes

// readKeptCredential is credfiles.ReadKeptCredential.
func readKeptCredential(h credfiles.FilesHost, path, engineUser string) (string, error) {
	return credfiles.ReadKeptCredential(h, path, engineUser)
}

// openEngineFile is credfiles.OpenEngineFile.
func openEngineFile(h credfiles.FilesHost, path, engineUser string) (*os.File, error) {
	return credfiles.OpenEngineFile(h, path, engineUser)
}
