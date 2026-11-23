package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"os"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/term"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// Environment variables the CLI reads.
const (
	envAdminURL = "BASALT_ADMIN_DATABASE_URL"
	envAgentURL = "BASALT_DATABASE_URL"
	envCacheDir = "BASALT_CACHE_DIR"
)

func newIO(ctx context.Context, std cli.Stdio, getenv func(string) string) *cli.IO {
	shell := appShell{}
	c := &cli.IO{
		Ctx: ctx, Stdin: bufio.NewReader(std.In), Stdout: std.Out, Stderr: std.Err,
		Getenv: getenv, Now: time.Now, Rand: rand.Reader, Goos: runtime.GOOS, Host: osHost{},
		Shell: shell,
		AgentLogin: func(ctx context.Context, dsn string) (cli.AgentConn, error) {
			return loginAsAgent(ctx, shell, dsn)
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
