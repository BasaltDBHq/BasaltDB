package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"os"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/term"

	"github.com/basaltdbhq/basaltdb/internal/handoff/in/handoffcli"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// Environment variables the CLI reads.
const envCacheDir = "BASALT_CACHE_DIR"

// NewIO is the CLI shell over the real machine, for a command line on std.
func NewIO(ctx context.Context, std cli.Stdio, getenv func(string) string) *cli.IO {
	shell := Shell{}
	c := &cli.IO{
		Ctx: ctx, Stdin: bufio.NewReader(std.In), Stdout: std.Out, Stderr: std.Err,
		Getenv: getenv, Now: time.Now, Rand: rand.Reader, Goos: runtime.GOOS, Host: OSHost{},
		Shell: shell,
		AgentLogin: func(ctx context.Context, dsn string) (cli.AgentConn, error) {
			return handoffcli.LoginAsAgent(ctx, shell, dsn)
		},
		Dial: func(ctx context.Context, dsn string) (*pgx.Conn, error) {
			return cli.Connect(ctx, shell, dsn)
		},
		FetchChain: cli.FetchChain,
		Width:      func() int { return cli.TerminalWidth(std.Out) },
	}
	c.Probe = probeLogin(c)
	stdin := std.In
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		c.Terminal = f
		c.Interactive = true
	}
	return c
}
