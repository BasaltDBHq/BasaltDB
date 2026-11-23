package app

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"
)

// The credential files of basalt init --remote and basalt service install
// (internal/setup/out/credfiles), forwarded to the CLI, which may not import
// an adapter.

// TrustedDir is a directory opened without following a link
// (credfiles.TrustedDir).
type TrustedDir = credfiles.TrustedDir

// PathCredFiles reaches the credential files by path (credfiles.PathCredFiles).
type PathCredFiles = credfiles.PathCredFiles

// MaxCredentialBytes bounds a credential (credfiles.MaxCredentialBytes).
const MaxCredentialBytes = credfiles.MaxCredentialBytes

// ReadKeptCredential is credfiles.ReadKeptCredential.
func ReadKeptCredential(h credfiles.FilesHost, path, engineUser string) (string, error) {
	return credfiles.ReadKeptCredential(h, path, engineUser)
}

// OpenEngineFile is credfiles.OpenEngineFile.
func OpenEngineFile(h credfiles.FilesHost, path, engineUser string) (*os.File, error) {
	return credfiles.OpenEngineFile(h, path, engineUser)
}
