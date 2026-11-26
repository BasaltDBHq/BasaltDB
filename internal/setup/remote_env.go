package setup

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// ErrUsage marks a usage error of basalt init --remote: a flag or an agent
// name it cannot take. The CLI answers it as its own usage error.
var ErrUsage = errors.New("usage")

// RemoteAgentConn is the agent's own connection init --remote reads with.
type RemoteAgentConn interface {
	Querier
	Close(ctx context.Context) error
}

// RemoteEnv is what basalt init --remote reaches through the CLI that runs
// it (setupcli fills it from its IO): the process and its configs, the
// agent's login, the clock, the network probes and stderr.
type RemoteEnv interface {
	// Euid is the process's effective uid.
	Euid() int
	// ConfigFlag is the config path the command line gave, "" for none.
	ConfigFlag() string
	// SystemConfig is the system-wide config path.
	SystemConfig() string
	// FindConfig is the config that serves agent (the CLI's search).
	FindConfig(agent string) (string, error)
	// UserConfigDir is the user's config directory.
	UserConfigDir() (string, error)
	// RefuseSecondConfig refuses a second config next to the one found.
	RefuseSecondConfig() error
	// LoadEngineConfig is the hardened read of the config at path: as
	// root, a plain file owned by root or its directory's owner, not
	// writable by group or others and reached without links.
	LoadEngineConfig(path string) (config.Config, error)
	// InvokingUID is the uid of the person who ran the command (sudo's).
	InvokingUID() (uint32, error)
	// InvokingUser is the OS user who ran the command.
	InvokingUser() (string, error)
	// AgentLogin logs in with the agent's credential dsn; LoginRefused
	// reports whether its error is the database refusing the login.
	AgentLogin(ctx context.Context, dsn string) (RemoteAgentConn, error)
	LoginRefused(err error) bool
	Now() time.Time
	Rand() io.Reader
	Goos() string
	// Probe tries a login to dsn for its TLS check (HardenedCredential).
	Probe(ctx context.Context, dsn string) error
	// FetchChain reads the chain host:port presents with the TLS handshake
	// alone; nil when the CLI reads none.
	FetchChain() func(ctx context.Context, host string, port int) ([]*x509.Certificate, error)
	// TerminalText is s safe to print on a terminal.
	TerminalText(s string) string
	// MCPBinary is the basalt binary the agent's MCP command runs.
	MCPBinary() string
	// MkdirStateDir makes the engine's state directory, with its mode.
	MkdirStateDir(path string) error
	// Stderr takes the run's notes.
	Stderr() io.Writer
}

// ChooseVault is the vault choice for an engine whose pages base is
// pagesURL: --vault when given, else the default (on with
// --operated-by=agent on the portal's pages, off otherwise, as with
// --dev-local-pages). --vault=on needs the portal's
// pages: a passkey on any other origin cannot sign on the portal, and the
// engine never dials out for them, so it is a usage error (ErrUsage).
// defaultWhy says why the default is off.
func ChooseVault(given VaultMode, operatedBy OperatedBy, pagesURL, defaultWhy string) (VaultChoice, error) {
	if given == VaultModeOn && pagesURL != links.Portal {
		return VaultChoice{}, fmt.Errorf("%w: --vault=on needs the portal's pages (%s), and these are %s: "+
			"a passkey registered there cannot sign on the portal, so the engine would not use the Vault", ErrUsage, links.Portal, pagesURL)
	}
	if operatedBy == OperatedByAgent && pagesURL == links.Portal {
		return VaultChoice{Given: given, Def: VaultModeOn, Why: "default for --operated-by=agent; --vault=off to turn it off"}, nil
	}
	return VaultChoice{Given: given, Def: VaultModeOff, Why: defaultWhy}, nil
}
