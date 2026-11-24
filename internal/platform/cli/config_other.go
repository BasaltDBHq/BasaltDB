//go:build !unix

package cli

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// loadConfigAsRoot: there is no root on this platform; Load as any user.
func loadConfigAsRoot(_ TrustedOpener, path string) (config.Config, []byte, error) {
	return config.LoadOpenRaw(path, os.Open)
}
