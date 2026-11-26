//go:build !unix

package credfiles

import (
	"os"
	"time"
)

// OpenRootCredFiles: see errRemoteUnsupported.
func OpenRootCredFiles(FilesHost, string, int) (Files, error) { return nil, errRemoteUnsupported }

// RootTrustedOwner: see errRemoteUnsupported.
func RootTrustedOwner(string) (int, error) { return 0, errRemoteUnsupported }

// OpenRootConfigDir: see errRemoteUnsupported.
func OpenRootConfigDir(FilesHost, string, int) (ConfigDir, error) { return nil, errRemoteUnsupported }

// RootEngineKey: see errRemoteUnsupported.
func RootEngineKey(FilesHost, string, string, ConfigDir, func() time.Time, os.FileMode) ([]byte, error) {
	return nil, errRemoteUnsupported
}
