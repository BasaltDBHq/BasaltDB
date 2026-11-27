package setupcli

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// basalt init --remote runs on the engine's machine, which the agent may
// control, with no admin credential (CONTRACT.md, basalt init --remote;
// CO-9). It takes --agent and nothing else: it keeps the agent's password
// here, writes engine.json with the pending setup, and prints the connect
// link of a setup code carrying only the password's SCRAM verifier. The
// person runs the code on the connect page. A pending setup that expired,
// was refused or names an address the engine refused is forgotten and
// replaced by a fresh code on the next run, with no flag.

const (
	flagRemote = "remote"
)

// IsRemote reports whether args ask for basalt init --remote.
func IsRemote(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != flagRemote {
			continue
		}
		on, err := strconv.ParseBool(value)
		return !hasValue || (err == nil && on)
	}
	return false
}

// RunRemote is basalt init --remote: it makes a setup code for an
// agent-operated engine and prints it. h is what it reaches outside the CLI.
func RunRemote(c *cli.IO, h Host, args []string) int {
	res, err := InitRemote(c, h, args)
	if err != nil {
		return c.Fail(err)
	}
	if err := PrintRemoteResult(c, res); err != nil {
		return c.Fail(err)
	}
	return cli.ExitOK
}

// InitRemote runs basalt init --remote and returns what it prints.
func InitRemote(c *cli.IO, h Host, args []string) (setup.RemoteInitResult, error) {
	f, err := parseInitRemote(c, args)
	if err != nil {
		return setup.RemoteInitResult{}, err
	}
	if err := setup.CheckBuildVersion(setup.BuildVersion()); err != nil {
		return setup.RemoteInitResult{}, err
	}
	// A config from before the last breaking release goes aside first: this
	// init then sets the agent up as a first run does.
	env := remoteEnv{c}
	path := env.ConfigFlag()
	if path == "" {
		path = env.SystemConfig()
		if c.Host.Euid() != 0 {
			if base, err := c.Host.UserConfigDir(); err == nil {
				path = config.UserPath(base)
			}
		}
	}
	if err := moveBreakingConfig(c, path); err != nil {
		return setup.RemoteInitResult{}, err
	}
	res, err := setup.InitRemote(c.Ctx, remoteEnv{c}, h, f)
	return res, cliUsage(err)
}

// parseInitRemote reads basalt init --remote's flags: --remote and
// --agent only (CONTRACT.md, CLI). The role's prefix and its statement
// timeout are fixed values.
func parseInitRemote(c *cli.IO, args []string) (setup.RemoteFlags, error) {
	f := setup.RemoteFlags{Prefix: cmp.Or(c.RolePrefix, guardmodel.DefaultPrefix), Timeout: guardmodel.DefaultRoleStatementTimeout, OperatedBy: setup.OperatedByAgent}
	var remote bool
	fs := c.Flags("init --remote")
	fs.BoolVar(&remote, flagRemote, false, "set up an agent on a bot's machine: prints the connect link the person opens")
	fs.StringVar(&f.Agent, "agent", "", "the agent's name (lowercase letters, digits, _); needed only when the engine serves more than one agent")
	if err := cli.Parse(fs, args); err != nil {
		return f, fmt.Errorf("%w (basalt init --remote takes only --agent; the connect page asks for the rest)", err)
	}
	f.ConfigPath = cmp.Or(c.Paths.Config, c.SystemConfig())
	return f, nil
}

// Host is what basalt init --remote reaches outside the CLI: the setup
// service's port (setup.RemoteHost).
type Host = setup.RemoteHost

// PrintRemoteResult prints the result: the connect link or the code in a
// block of its own, its fingerprint and what the person does.
func PrintRemoteResult(c *cli.IO, res setup.RemoteInitResult) error {
	if res.Reused {
		fmt.Fprintln(c.Stderr, "basalt: a setup code is pending for this agent; here it is again")
	}
	expires, err := time.Parse(time.RFC3339, res.ExpiresAt)
	if err != nil {
		return err
	}
	if res.ConnectOnly {
		if err := printConnectOnly(c, res, expires); err != nil {
			return err
		}
		return printRemoteMCP(c, res)
	}
	_, err = fmt.Fprintf(c.Stdout, "Setup code for %s (%s), valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
		res.Agent, res.Kind, expires.UTC().Format("2006-01-02 15:04 UTC"), res.Code, res.Fingerprint, res.PersonMessage)
	if err == nil && res.PasteAtPortal {
		// The link is over the budget: no link is printed, the code is
		// pasted at the connect page instead.
		_, err = fmt.Fprintf(c.Stdout, "\nTo use Basalt Vault, a hosted service, paste the setup code at %s.\n", strings.TrimPrefix(links.Portal+links.ConnectPath, "https://"))
	}
	if err != nil {
		return err
	}
	return printRemoteMCP(c, res)
}

// printRemoteMCP prints the basalt mcp command the agent registers.
func printRemoteMCP(c *cli.IO, res setup.RemoteInitResult) error {
	_, err := fmt.Fprintf(c.Stdout, "then add this MCP server to the agent's client, running as OS user %s:\n  %s\n",
		res.OSUser, guidance.ShellJoin(res.MCPCommand))
	return err
}

// printConnectOnly prints a connect-only code's result: the connect link
// and the fingerprint, or, over the link budget,
// the code to paste at the connect page.
func printConnectOnly(c *cli.IO, res setup.RemoteInitResult, expires time.Time) error {
	until := expires.UTC().Format("2006-01-02 15:04 UTC")
	if res.ConnectURL == "" {
		_, err := fmt.Fprintf(c.Stdout, "Setup code for %s (%s), for the connect page only, valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
			res.Agent, res.Kind, until, res.Code, res.Fingerprint, res.PersonMessage)
		return err
	}
	_, err := fmt.Fprintf(c.Stdout, "Connect link for %s (%s), valid until %s:\n\n%s\n\nSetup fingerprint: %s\n\n%s\n",
		res.Agent, res.Kind, until, res.ConnectURL, res.Fingerprint, res.PersonMessage)
	return err
}

// remoteEnv is the CLI's IO as the setup service's RemoteEnv.
type remoteEnv struct{ c *cli.IO }

func (e remoteEnv) Euid() int                               { return e.c.Host.Euid() }
func (e remoteEnv) ConfigFlag() string                      { return e.c.Paths.Config }
func (e remoteEnv) SystemConfig() string                    { return e.c.SystemConfig() }
func (e remoteEnv) FindConfig(agent string) (string, error) { return e.c.FindConfig(agent) }
func (e remoteEnv) UserConfigDir() (string, error)          { return e.c.Host.UserConfigDir() }
func (e remoteEnv) RefuseSecondConfig() error               { return e.c.RefuseSecondConfig() }
func (e remoteEnv) InvokingUID() (uint32, error)            { return InvokingUID(e.c) }
func (e remoteEnv) InvokingUser() (string, error)           { return cli.InvokingUser() }
func (e remoteEnv) LoginRefused(err error) bool             { return errors.Is(err, handoff.ErrLoginRefused) }
func (e remoteEnv) Now() time.Time                          { return e.c.Now() }
func (e remoteEnv) Rand() io.Reader                         { return e.c.Rand }
func (e remoteEnv) Goos() string                            { return e.c.Goos }
func (e remoteEnv) TerminalText(s string) string            { return cli.TerminalText(s) }
func (e remoteEnv) MCPBinary() string                       { return setup.MCPBinary(e.c.Host) }
func (e remoteEnv) Stderr() io.Writer                       { return e.c.Stderr }

// LoadEngineConfig is the hardened read (cli.LoadEngineConfig).
func (e remoteEnv) LoadEngineConfig(path string) (config.Config, error) {
	return cli.LoadEngineConfig(e.c, path)
}

// AgentLogin is the CLI's login: the connection it returns is the
// service's port as it is, and carries the driver connection for the
// adapter that runs the guard's reads on it.
func (e remoteEnv) AgentLogin(ctx context.Context, dsn string) (setup.RemoteAgentConn, error) {
	conn, err := e.c.AgentLogin(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (e remoteEnv) Probe(ctx context.Context, dsn string) error { return e.c.Probe(ctx, dsn) }

func (e remoteEnv) FetchChain() func(ctx context.Context, host string, port int) ([]*x509.Certificate, error) {
	return e.c.FetchChain
}

// MkdirStateDir makes the engine's state directory with the engine's mode.
func (e remoteEnv) MkdirStateDir(path string) error { return os.MkdirAll(path, engine.StateDirMode) }

// cliUsage marks the setup service's usage errors as the CLI's (exit 2),
// keeping their text.
func cliUsage(err error) error {
	if errors.Is(err, setup.ErrUsage) {
		return usageError{err}
	}
	return err
}

type usageError struct{ error }

func (e usageError) Is(target error) bool { return target == cli.ErrUsage }
func (e usageError) Unwrap() error        { return e.error }
