package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/term"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Environment variables the CLI reads.
const (
	envAdminURL = "BASALT_ADMIN_DATABASE_URL"
	envAgentURL = "BASALT_DATABASE_URL"
	envCacheDir = "BASALT_CACHE_DIR"
)

// cliIO is everything a command touches outside its arguments, so tests
// can drive commands without a terminal.
type cliIO struct {
	ctx    context.Context
	stdin  *bufio.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	now    func() time.Time
	// rand is the randomness source (crypto/rand outside tests).
	rand io.Reader
	// terminal is the stdin file when it is a terminal, for hidden input.
	terminal *os.File
	// interactive is true when a person answers at a terminal: init asks
	// its setup questions only then.
	interactive bool
	// width is the terminal's width in columns, 0 when stdout is no
	// terminal; tests set it.
	width func() int
	// systemConfigPath replaces the system path of engine.json in tests
	// (empty: config.DefaultPath(goos)).
	systemConfigPath string
	// paths point commands at temporary files in tests.
	paths pathOverrides
	// rolePrefix replaces guard.DefaultPrefix for basalt init --remote's
	// first code, before any credential names the role; tests set it, so
	// tests sharing a database server keep their roles apart.
	rolePrefix string
	// goos is the platform whose paths and service manager init uses.
	goos string
	// host runs what init does outside Postgres (sudo, the service probe,
	// claude mcp add); tests use a fake.
	host host
	// shell is what the shell reaches outside itself: connections, the
	// trust profiles and the hardened config open (appShell).
	shell shellHost
	// agentLogin logs in with the agent's credential (basalt init
	// --remote): nil and no error when the database refuses the login.
	agentLogin func(ctx context.Context, dsn string) (agentConn, error)
	// dial opens a database connection (connect outside tests).
	dial func(ctx context.Context, dsn string) (*pgx.Conn, error)
	// probe tries a login bound to fail, to confirm a credential's TLS
	// protection (hardenedCredential); probeLogin outside tests.
	probe func(ctx context.Context, dsn string) error
	// fetchChain reads the chain a database presents with the TLS
	// handshake alone, before a pin is offered (fetchChain outside tests;
	// nil offers no pin).
	fetchChain func(ctx context.Context, host string, port int) ([]*x509.Certificate, error)
}

// shellHost is what the CLI shell reaches outside itself: database
// connections, the trust profiles a connection uses and the hardened open
// of a config file. The shell names no adapter; appShell is the real one.
type shellHost interface {
	// Connect opens one connection, usable through a transaction pooler.
	Connect(ctx context.Context, dsn string) (*pgx.Conn, error)
	// WithCertificateHint is err with what can fix it, when it is a
	// certificate of dsn's host that did not verify.
	WithCertificateHint(dsn string, err error) error
	// CertificateNotVerified reports whether err is a server certificate
	// that did not verify.
	CertificateNotVerified(err error) bool
	// CurrentTrustProfileSet is the trust profiles a connection opened now
	// uses.
	CurrentTrustProfileSet() *trustprofile.Set
	// OSOpenTrustedFile opens path read-only for root, never through a
	// symlink, its directory trusted only from root or owner.
	OSOpenTrustedFile(path string, owner int) (*os.File, error)
}

func newIO(ctx context.Context, std stdio, getenv func(string) string) *cliIO {
	shell := appShell{}
	c := &cliIO{
		ctx: ctx, stdin: bufio.NewReader(std.in), stdout: std.out, stderr: std.err,
		getenv: getenv, now: time.Now, rand: rand.Reader, goos: runtime.GOOS, host: osHost{},
		shell: shell,
		agentLogin: func(ctx context.Context, dsn string) (agentConn, error) {
			return loginAsAgent(ctx, shell, dsn)
		},
		dial: func(ctx context.Context, dsn string) (*pgx.Conn, error) {
			return connect(ctx, shell, dsn)
		},
		fetchChain: fetchChain,
		width:      func() int { return terminalWidth(std.out) },
	}
	c.probe = probeLogin(c)
	stdin := std.in
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		c.terminal = f
		c.interactive = true
	}
	return c
}

// terminalWidth is w's width in columns when it is a terminal, else 0.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	cols, _, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return cols
}

// fail prints err and returns its exit code. An error can carry database
// text (a Postgres detail quotes the values an agent wrote), so it is
// escaped (cli.TerminalText) and its later lines are indented: no line of
// it can pass for a line basalt printed.
func (c *cliIO) fail(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return cli.ExitOK // the flag set already printed its usage
	}
	msg := strings.ReplaceAll(cli.TerminalText(err.Error()), "\n", "\n"+failIndent)
	fmt.Fprintf(c.stderr, "basalt: %s\n", msg)
	if errors.Is(err, cli.ErrUsage) {
		return cli.ExitUsage
	}
	return cli.ExitError
}

// failIndent starts each later line of an error printed by fail.
const failIndent = "  "

func (c *cliIO) flags(name string) *flag.FlagSet {
	fs := cli.NewFlagSet(name)
	fs.SetOutput(c.stderr)
	return fs
}

// connect opens one connection, usable through a transaction pooler
// (pgdial).
func connect(ctx context.Context, sh shellHost, dsn string) (*pgx.Conn, error) {
	conn, err := sh.Connect(ctx, dsn)
	if err != nil {
		if changed := rootChanged(ctx, sh, dsn, err); changed != nil {
			return nil, fmt.Errorf("connect: %w", changed)
		}
		return nil, fmt.Errorf("connect: %w", sh.WithCertificateHint(dsn, err))
	}
	return conn, nil
}

// withIO adapts a guard command to the command table: open builds the
// command's cliIO (newIO).
func withIO(open func(context.Context, stdio, func(string) string) *cliIO,
	f func(c *cliIO, args []string) int,
) func(context.Context, []string, stdio) int {
	return func(ctx context.Context, args []string, std stdio) int {
		return f(open(ctx, std, os.Getenv), args)
	}
}
