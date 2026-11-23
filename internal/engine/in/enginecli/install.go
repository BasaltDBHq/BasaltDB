package enginecli

import (
	"errors"
	"fmt"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// InstallHost is what installing the engine service reaches outside the
// CLI: the service's fixed script, its unit's path and its default OS user.
type InstallHost interface {
	// OSInstallScript is the first install's fixed script for binary.
	OSInstallScript(goos, binary string) (string, error)
	// OSDefaultUser is the OS user the engine service runs as.
	OSDefaultUser(goos string) string
	// OSUnitPath is the installed engine service unit's path.
	OSUnitPath(goos string) string
}

// EnsureService installs the engine service through the system's
// administrator dialog when it is not installed yet: one password, in the
// dialog. It never falls back to running the engine as the person.
func EnsureService(c *cli.IO, h InstallHost) error {
	if c.Host.System(io.Discard, io.Discard).Exists(h.OSUnitPath(c.Goos)) {
		return nil
	}
	if err := c.Host.DialogAvailable(c.Goos); err != nil {
		return noDialog(err)
	}
	bin, script, err := dialogScript(c, h)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Stderr, "basalt: asking for your password in the system's administrator dialog to install the engine service as %s; it runs:\n  %s\n",
		h.OSDefaultUser(c.Goos), cli.ShellJoin(engine.DialogEngineArgs(c.Goos, bin)))
	if err := c.Host.AdminDialog(c.Ctx, c.Goos, servicespec.InstallPrompt, script, c.Stderr); err != nil {
		if errors.Is(err, servicespec.ErrNoDialog) {
			return noDialog(err)
		}
		return err
	}
	return nil
}

// dialogScript is the first install's fixed script for the running
// binary, with every link resolved and checked as root would run it. The
// script comes from h.
func dialogScript(c *cli.IO, h InstallHost) (bin, script string, err error) {
	bin, err = c.Host.ResolvedExecutable()
	if err != nil {
		return "", "", fmt.Errorf("the engine service runs this basalt binary by its own path, and its links do not resolve: %w", err)
	}
	if err := c.Host.System(c.Stderr, c.Stderr).CheckBinary(bin); err != nil {
		return "", "", err
	}
	script, err = h.OSInstallScript(c.Goos, bin)
	return bin, script, err
}

// noDialog is init's stop when no administrator dialog can be shown: it
// never falls back to running the engine as the person's user.
func noDialog(err error) error {
	return fmt.Errorf("basalt init installs the engine service through the system's administrator dialog, which only you can answer, and it cannot be shown here (%w). "+
		"Run basalt init again in a desktop session on this machine; basalt does not run the engine as your user instead", err)
}
