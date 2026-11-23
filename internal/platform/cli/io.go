package cli

import (
	"bufio"
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

// AgentConn is the agent's own connection init --remote reads with.
type AgentConn interface {
	pgquerier.Querier
	Close(ctx context.Context) error
}

// IO is everything a command touches outside its arguments, so tests
// can drive commands without a terminal.
type IO struct {
	Ctx    context.Context
	Stdin  *bufio.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Now    func() time.Time
	// Rand is the randomness source (crypto/rand outside tests).
	Rand io.Reader
	// Terminal is the stdin file when it is a terminal, for hidden input.
	Terminal *os.File
	// Interactive is true when a person answers at a terminal: init asks
	// its setup questions only then.
	Interactive bool
	// Width is the terminal's width in columns, 0 when stdout is no
	// terminal; tests set it.
	Width func() int
	// SystemConfigPath replaces the system path of engine.json in tests
	// (empty: config.DefaultPath(goos)).
	SystemConfigPath string
	// Paths point commands at temporary files in tests.
	Paths PathOverrides
	// RolePrefix replaces guard.DefaultPrefix for basalt init --remote's
	// first code, before any credential names the role; tests set it, so
	// tests sharing a database server keep their roles apart.
	RolePrefix string
	// Goos is the platform whose paths and service manager init uses.
	Goos string
	// Host runs what init does outside Postgres (sudo, the service probe,
	// claude mcp add); tests use a fake.
	Host Machine
	// Shell is what the shell reaches outside itself: connections, the
	// trust profiles and the hardened config open.
	Shell Host
	// AgentLogin logs in with the agent's credential (basalt init
	// --remote): nil and no error when the database refuses the login.
	AgentLogin func(ctx context.Context, dsn string) (AgentConn, error)
	// Dial opens a database connection (Connect outside tests).
	Dial func(ctx context.Context, dsn string) (*pgx.Conn, error)
	// Probe tries a login bound to fail, to confirm a credential's TLS
	// protection (hardenedCredential); probeLogin outside tests.
	Probe func(ctx context.Context, dsn string) error
	// FetchChain reads the chain a database presents with the TLS
	// handshake alone, before a pin is offered (FetchChain outside tests;
	// nil offers no pin).
	FetchChain func(ctx context.Context, host string, port int) ([]*x509.Certificate, error)
}

// Fail prints err and returns its exit code. An error can carry database
// text (a Postgres detail quotes the values an agent wrote), so it is
// escaped (TerminalText) and its later lines are indented: no line of
// it can pass for a line basalt printed.
func (c *IO) Fail(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK // the flag set already printed its usage
	}
	msg := strings.ReplaceAll(TerminalText(err.Error()), "\n", "\n"+failIndent)
	fmt.Fprintf(c.Stderr, "basalt: %s\n", msg)
	if errors.Is(err, ErrUsage) {
		return ExitUsage
	}
	return ExitError
}

// failIndent starts each later line of an error printed by Fail.
const failIndent = "  "

// Flags is the named flag set, printing to Stderr.
func (c *IO) Flags(name string) *flag.FlagSet {
	fs := NewFlagSet(name)
	fs.SetOutput(c.Stderr)
	return fs
}

// SystemConfig is the system path of engine.json; tests point it at a
// temporary file.
func (c *IO) SystemConfig() string {
	return cmp.Or(c.SystemConfigPath, config.DefaultPath(c.Goos))
}

// PathOverrides point a command at temporary files in tests: the engine
// config, and for init the socket directory and the credential file. The
// zero value finds everything by itself.
type PathOverrides struct{ Config, SocketDir, CredFile string }

// FindConfig is the engine.json this command uses ([Config discovery]).
func (c *IO) FindConfig() (string, error) {
	if c.Paths.Config != "" {
		return c.Paths.Config, nil
	}
	return DiscoverConfig(c.Host, c.SystemConfig())
}

// RefuseSecondConfig is the error of a setup that would write the person's
// own engine.json while the system one exists: a second config would make
// every later command stop on two. Root and the tests' path overrides write
// where they are told.
func (c *IO) RefuseSecondConfig() error {
	if c.Host.Euid() == 0 || c.Paths.Config != "" {
		return nil
	}
	system := c.SystemConfig()
	if _, err := os.Stat(system); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("the engine config %s exists already: run basalt init as its owner (with sudo), not as this user", system)
}

// WithIO adapts a guard command to the command table: open builds the
// command's IO.
func WithIO(open func(context.Context, Stdio, func(string) string) *IO,
	f func(c *IO, args []string) int,
) func(context.Context, []string, Stdio) int {
	return func(ctx context.Context, args []string, std Stdio) int {
		return f(open(ctx, std, os.Getenv), args)
	}
}
