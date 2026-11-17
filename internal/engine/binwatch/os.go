package binwatch

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/updatecheck"
)

// OS is the real System.
type OS struct{}

var _ System = OS{}

// Trusted is the root-only check of basalt service install.
func (OS) Trusted(path string) error { return service.OSSystem{}.CheckBinary(path) }

// probeWaitDelay bounds the wait for the probe's output after it exits or
// is killed.
const probeWaitDelay = time.Second

// maxProbeOutput bounds what basalt version may print.
const maxProbeOutput = 4096

// Probe runs path version with the update check off, so the probe never
// reaches the network.
func (OS) Probe(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Env = append(os.Environ(), updatecheck.EnvDisable+"=off")
	var out limitedBuffer
	cmd.Stdout = &out
	// A child the probed binary leaves holding stdout must not keep Run
	// waiting after the timeout.
	cmd.WaitDelay = probeWaitDelay
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return parseVersion(out.String())
}

// limitedBuffer keeps the first maxProbeOutput bytes written to it.
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxProbeOutput - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
