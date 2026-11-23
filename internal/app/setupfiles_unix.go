//go:build unix

package app

import "github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"

// OpenRootCredFiles is credfiles.OpenRootCredFiles.
func OpenRootCredFiles(h credfiles.FilesHost, dir string, trusted int) (credfiles.RootCredFiles, error) {
	return credfiles.OpenRootCredFiles(h, dir, trusted)
}

// CredentialOwner is credfiles.CredentialOwner.
func CredentialOwner(dirUID int) int { return credfiles.CredentialOwner(dirUID) }
