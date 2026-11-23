//go:build unix

package app

import "github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"

// credentialOwner is credfiles.CredentialOwner.
func credentialOwner(dirUID int) int { return credfiles.CredentialOwner(dirUID) }
