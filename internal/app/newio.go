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
// newIO is the CLI shell over the real machine, for a command line on std.
func newIO(ctx context.Context, std cli.Stdio, getenv func(string) string) *cli.IO {
	sh := shell{}
	c := &cli.IO{
		Ctx: ctx, Stdin: bufio.NewReader(std.In), Stdout: std.Out, Stderr: std.Err,
		Getenv: getenv, Now: time.Now, Rand: rand.Reader, Goos: runtime.GOOS, Host: osHost{},
		Shell: sh,
		AgentLogin: func(ctx context.Context, dsn string) (cli.AgentConn, error) {
			return handoffcli.LoginAsAgent(ctx, sh, pgErrors{}, dsn)
		},
		Dial: func(ctx context.Context, dsn string) (*pgx.Conn, error) {
			return cli.Connect(ctx, sh, dsn)
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
