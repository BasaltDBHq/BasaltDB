//go:build unix

package app

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// The YES writes the pin the engine confirmed to trust.d, once; it never
// replaces a profile that covers the host by then.
func TestHandoffFilesWritePin(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o700))
	f := handoff.SetupFiles{ConfigPath: filepath.Join(dir, "engine.json"), Agent: "lead_bot", Pins: trustPins{}}
	const host = "db.example.com"
	pinOf := func(t *testing.T) handoff.Pin {
		t.Helper()
		ca, _ := trustprofiletest.Chain(t, host)
		pf, err := trustprofile.NewPin(host, ca, false)
		require.NoError(t, err)
		return handoff.Pin{Profile: pf.Profile, Top: ca}
	}
	pin := pinOf(t)
	require.NoError(t, f.WritePin(host, pin))
	got := trustdir.Set(f.ConfigPath).For(host)
	require.NotNil(t, got)
	require.Equal(t, trustprofile.PinName(host), got.Name)
	require.Equal(t, []*x509.Certificate{pin.Top}, got.Certificates())
	require.NoError(t, f.WritePin(host, pin), "the same pin again writes nothing")

	err = f.WritePin(host, pinOf(t))
	require.ErrorContains(t, err, "covers "+host)
	require.True(t, trustdir.Set(f.ConfigPath).For(host).Certificates()[0].Equal(pin.Top), "the first pin stays")
}
