package main

import (
	"bufio"
	"context"
	"crypto/rand"
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

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
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
	// rawRead reads a pasted line from terminal with canonical mode off
	// (nil: readTerminalLine); tests replace it.
	rawRead rawLineReader
	// interactive is true when a person answers at a terminal: init asks
	// its setup questions only then.
	interactive bool
	// tty overrides the terminal check of printLink; tests set it.
	tty func(io.Writer) bool
	// width is the terminal's width in columns, 0 when stdout is no
	// terminal; tests set it.
	width func() int
	// goos is the platform whose paths and service manager init uses.
	goos string
	// host runs what init does outside Postgres (sudo, the service probe,
	// claude mcp add); tests use a fake.
	host host
	// agentLogin logs in with the agent's credential (basalt init
	// --remote): nil and no error when the database refuses the login.
	agentLogin func(ctx context.Context, dsn string) (agentConn, error)
	// dial opens a database connection (connect outside tests).
	dial func(ctx context.Context, dsn string) (*pgx.Conn, error)
	// engine tells service mode from same-user mode and finds the person
	// socket (log, approve, revert); tests replace it.
	engine engineAccess
	// probe fetches an engine address's /v1/engine for basalt tunnel
	// (engineProbe outside tests).
	probe func(ctx context.Context, url string) (probeAnswer, error)
}

func newIO(ctx context.Context, std stdio, getenv func(string) string) *cliIO {
	c := &cliIO{
		ctx: ctx, stdin: bufio.NewReader(std.in), stdout: std.out, stderr: std.err,
		getenv: getenv, now: time.Now, rand: rand.Reader, goos: runtime.GOOS, host: osHost{},
		agentLogin: loginAsAgent,
		dial:       connect,
		engine:     osEngineAccess(runtime.GOOS),
		probe:      engineProbe,
		width:      func() int { return terminalWidth(std.out) },
	}
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

// errUsage marks an error as a usage error (exit 2).
var errUsage = errors.New("usage")

// fail prints err and returns its exit code. An error can carry database
// text (a Postgres detail quotes the values an agent wrote), so it is
// escaped (terminalText) and its later lines are indented: no line of it
// can pass for a line basalt printed.
func (c *cliIO) fail(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK // the flag set already printed its usage
	}
	msg := strings.ReplaceAll(terminalText(err.Error()), "\n", "\n"+failIndent)
	fmt.Fprintf(c.stderr, "basalt: %s\n", msg)
	if errors.Is(err, errUsage) {
		return exitUsage
	}
	return exitError
}

// failIndent starts each later line of an error printed by fail.
const failIndent = "  "

func (c *cliIO) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	return fs
}

// parse parses args and refuses positional arguments.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	return nil
}

// line reads one line from stdin without the newline.
func (c *cliIO) line() (string, error) {
	s, err := c.stdin.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || s == "") {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// adminURL takes the admin connection string from the environment or a
// hidden prompt. It is used for this command only and never written.
func (c *cliIO) adminURL() (string, error) {
	if v := c.getenv(envAdminURL); v != "" {
		return v, nil
	}
	fmt.Fprint(c.stderr, "Admin connection string (used once, never stored): ")
	if c.terminal != nil {
		b, err := term.ReadPassword(int(c.terminal.Fd()))
		fmt.Fprintln(c.stderr)
		return strings.TrimSpace(string(b)), err
	}
	return c.line()
}

// confirm asks a yes/no question on stderr.
func (c *cliIO) confirm(question string) (bool, error) {
	fmt.Fprintf(c.stderr, "%s [y/N] ", question)
	answer, err := c.line()
	if err != nil {
		return false, err
	}
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}

// confirmYes asks a yes/no question whose default (an empty answer) is yes.
func (c *cliIO) confirmYes(question string) (bool, error) {
	fmt.Fprintf(c.stderr, "%s [Y/n] ", question)
	answer, err := c.line()
	if err != nil {
		return false, err
	}
	return answer == "" || strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}

// connect opens one connection, usable through a transaction pooler
// (pgdial).
func connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	conn, err := pgdial.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return conn, nil
}

// withIO adapts a guard command to the command table.
func withIO(f func(c *cliIO, args []string) int) func(context.Context, []string, stdio) int {
	return func(ctx context.Context, args []string, std stdio) int {
		return f(newIO(ctx, std, os.Getenv), args)
	}
}

// splitList splits a comma-separated flag value.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
