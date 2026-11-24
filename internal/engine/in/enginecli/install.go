package enginecli

import (
	"errors"
	"fmt"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// InstallHost is what installing the engine service reaches outside the
// CLI: the service's fixed script, its unit's path and its default OS user.
type InstallHost interface {
	// OSInstallScript is the first install's fixed script for binary, which
	// it copies to OSServiceBinary unless binary is that copy.
	OSInstallScript(goos, binary string) (string, error)
	// OSServiceBinary is the engine service's own copy of basalt, root's:
	// the binary its unit runs.
	OSServiceBinary(goos string) string
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
	service := h.OSServiceBinary(c.Goos)
	copying := ""
	if bin != service {
		copying = fmt.Sprintf("copy %s to %s, root's, and ", bin, service)
	}
	fmt.Fprintf(c.Stderr, "basalt: asking for your password in the system's administrator dialog to %sinstall the engine service as %s; it runs:\n  %s\n",
		copying, h.OSDefaultUser(c.Goos), guidance.ShellJoin(engine.DialogEngineArgs(c.Goos, service)))
	if err := c.Host.AdminDialog(c.Ctx, c.Goos, servicespec.InstallPrompt, script, c.Stderr); err != nil {
		if errors.Is(err, servicespec.ErrNoDialog) {
			return noDialog(err)
		}
		return err
	}
	// The script checked the copy as root; check it again as the unit
	// will run it.
	return c.Host.System(c.Stderr, c.Stderr).CheckBinary(service)
}

// dialogScript is the first install's fixed script for the running
// binary, with every link resolved: the script copies it to the service's
// own path, root's, so it may sit in a folder the person's account owns (a
// Homebrew prefix). The script comes from h.
func dialogScript(c *cli.IO, h InstallHost) (bin, script string, err error) {
	bin, err = c.Host.ResolvedExecutable()
	if err != nil {
		return "", "", fmt.Errorf("the engine service runs a copy of this basalt binary, and its links do not resolve: %w", err)
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
