//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// --no-service is a flag of basalt init only: basalt service install's
// unprotected-binary error does not suggest it.
func TestServiceInstallBinaryErrorHasNoInitHint(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("as root a binary in a root-owned temp directory may pass the check")
	}
	bin := filepath.Join(t.TempDir(), "basalt")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))
	var out, errb bytes.Buffer

	code := runServiceAt(context.Background(), []string{"install", "--binary", bin, "--dry-run"},
		stdio{in: strings.NewReader(""), out: &out, err: &errb}, tempConfig(t))

	require.Equal(t, exitError, code, errb.String())
	require.Contains(t, errb.String(), "only root may be able to change it")
	require.NotContains(t, errb.String(), "--no-service")
}
