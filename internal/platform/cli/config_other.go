//go:build !unix

package cli

import "github.com/basaltdbhq/basaltdb/internal/config"

// loadConfigAsRoot: there is no root on this platform; Load as any user.
func loadConfigAsRoot(_ Host, path string) (config.Config, int, error) {
	cfg, err := config.Load(path)
	return cfg, 0, err
}
