package app

import (
	"context"
	"io"
	"os"
	"os/exec"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/lib/browser"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

// goosDarwin is runtime.GOOS on macOS.
const goosDarwin = "darwin"

// osHost is the real machine, the CLI's Machine: its steps are
// osservice's, given the engine's paths and header here.
type osHost struct{}

func (osHost) Euid() int                      { return os.Geteuid() }
func (osHost) Executable() (string, error)    { return cli.ShimExecutable() }
func (osHost) UserConfigDir() (string, error) { return os.UserConfigDir() }
func (osHost) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (osHost) ResolvedExecutable() (string, error) { return osservice.ResolvedExecutable() }

func (osHost) DialogAvailable(goos string) error { return osservice.DialogAvailable(goos) }

func (osHost) AdminDialog(ctx context.Context, goos, prompt, script string, out io.Writer) error {
	return osservice.AdminDialog(ctx, goos, prompt, script, out)
}

func (osHost) SetupState(ctx context.Context, origin string) (string, error) {
	return osservice.SetupState(ctx, origin, localsetup.SetupCheckPath)
}

func (osHost) EngineBuild(ctx context.Context, origin string) (string, error) {
	return osservice.EngineBuild(ctx, origin, pageserver.BuildHeader)
}

func (osHost) ServiceRuns(ctx context.Context, goos string) (int, int, error) {
	return osservice.ServiceRuns(ctx, goos)
}

func (osHost) Sudo(ctx context.Context, args []string, stdin string, out, errw io.Writer) error {
	return osservice.Sudo(ctx, args, stdin, out, errw)
}

func (osHost) Run(ctx context.Context, args []string, out, errw io.Writer) error {
	return osservice.Run(ctx, args, out, errw)
}

func (osHost) OpenURL(ctx context.Context, link string) error {
	return browser.Open(ctx, link)
}

func (osHost) PagesUp(ctx context.Context, origin string) bool { return osservice.PagesUp(ctx, origin) }

func (osHost) System(out, errw io.Writer) cli.System {
	return osservice.OSSystem{Stdout: out, Stderr: errw}
}

func (osHost) Probe(ctx context.Context, socket string) error { return osservice.Probe(ctx, socket) }

func (osHost) EngineLog(ctx context.Context, goos string) (string, error) {
	return osservice.EngineLog(ctx, goos, engine.DarwinEngineLog)
}
