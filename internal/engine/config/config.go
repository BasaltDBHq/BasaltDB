// Package config is the engine's configuration file, written by basalt init:
// where the per-agent sockets live, which OS user may connect to each agent's
// socket, where that agent's scoped Postgres credential is, and the limits on
// agent statements. The shim reads only the default socket directory from
// here and never a credential.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// Platform defaults. The engine service runs as its own OS user; the config
// and credential files are readable by that user only.
const (
	linuxConfigPath  = "/etc/basalt/engine.json"
	linuxSocketDir   = "/run/basalt"
	goosDarwin       = "darwin"
	darwinConfigDir  = "/Library/Application Support/Basalt"
	darwinConfigPath = darwinConfigDir + "/engine.json"
	darwinSocketDir  = darwinConfigDir + "/run"
	// linuxStateDir is the systemd StateDirectory of the engine unit.
	linuxStateDir  = "/var/lib/basalt"
	darwinStateDir = darwinConfigDir + "/state"

	// credentialPermMask is the permission bits a credential file must not
	// have: nothing for group or others.
	credentialPermMask = 0o077
	// maxConfigBytes bounds the config and credential files read at start.
	maxConfigBytes = 1 << 20
	socketSuffix   = ".sock"
)

// DefaultPath is the config file location on goos.
func DefaultPath(goos string) string {
	if goos == goosDarwin {
		return darwinConfigPath
	}
	return linuxConfigPath
}

// DefaultSocketDir is the socket directory on goos.
func DefaultSocketDir(goos string) string {
	if goos == goosDarwin {
		return darwinSocketDir
	}
	return linuxSocketDir
}

// DefaultStateDir is the engine's state directory on goos.
func DefaultStateDir(goos string) string {
	if goos == goosDarwin {
		return darwinStateDir
	}
	return linuxStateDir
}

// StateDirFor is c.StateDir, or the default on goos when it is empty.
func (c Config) StateDirFor(goos string) string {
	if c.StateDir != "" {
		return c.StateDir
	}
	return DefaultStateDir(goos)
}

// Config is the engine configuration file.
type Config struct {
	// SocketDir holds one socket per agent, <SocketDir>/<name>.sock.
	SocketDir string  `json:"socketDir" validate:"required"`
	Agents    []Agent `json:"agents" validate:"required,min=1,unique=Name,dive"`
	Limits    Limits  `json:"limits"`
	// StateDir keeps the engine's own state: each agent's last verified
	// ledger chain head. Empty means DefaultStateDir.
	StateDir string `json:"stateDir,omitempty"`
	// PagesURL is the base URL of the approval, revert and registration
	// pages (links): http://localhost:<port> for the engine's own pages,
	// the default (links.DefaultLocal), or the hosted console. See
	// PagesBase.
	PagesURL string `json:"pagesUrl,omitempty"`
	// ApprovalPage is the older key: only its origin is used, when
	// pagesUrl is not set. basalt init writes pagesUrl.
	ApprovalPage string `json:"approvalPage,omitempty" validate:"omitempty,url"`
	// PagesAddr is where the engine serves the approval and revert pages on
	// loopback (see Pages); "off" disables them, empty is the default.
	PagesAddr string `json:"pagesAddr,omitempty"`
	// Notify says where the person hears about held writes.
	Notify Notify `json:"notify,omitzero"`
	// OperatedBy is who runs machine steps on this engine's machine:
	// PERSON (also when empty) or AGENT (CONTRACT.md, Who operates the
	// engine).
	OperatedBy string `json:"operatedBy,omitempty" validate:"omitempty,oneof=PERSON AGENT"`
}

// AgentOperated reports whether the agent runs this engine's machine steps.
func (c Config) AgentOperated() bool { return c.OperatedBy == mcpcontract.OperatedByAgent }

// Notify configures notifications. Every field is optional.
type Notify struct {
	Telegram *Telegram `json:"telegram,omitempty"`
}

// Telegram sends held-write links through a bot to one chat. The bot token
// sits in its own file, mode 0600, never in this config.
type Telegram struct {
	BotTokenFile string `json:"botTokenFile" validate:"required"`
	ChatID       string `json:"chatId" validate:"required,max=64"`
}

// Agent is one agent the engine serves.
type Agent struct {
	// Name is the agent's name; its Postgres role is basalt_agent_<name>.
	Name string `json:"name" validate:"required,agentname"`
	// OSUser is the only OS user allowed to connect to the agent's socket.
	OSUser string `json:"osUser" validate:"required"`
	// CredentialFile holds the agent role's Postgres URL, mode 0600.
	CredentialFile string `json:"credentialFile" validate:"required"`
	// InitArgs are the flags basalt init was run with for this agent (never
	// the admin connection string, a password or a one-shot flag), so a
	// step can name the init command again. See agent.NewCommands.
	InitArgs []string `json:"initArgs,omitempty"`
	// Setup is the pending setup code basalt init --remote made for this
	// agent; nil when none is pending.
	Setup *Setup `json:"setup,omitempty"`
}

// Setup is an agent's pending setup (CONTRACT.md, basalt init --remote):
// what status and a re-run of init hand out again. Nothing secret: the
// code carries the password's verifier, not the password.
type Setup struct {
	SetupID      string `json:"setupId" validate:"required,uuid"`
	Kind         string `json:"kind" validate:"oneof=INSTALL AGENT UPGRADE"`
	GuardVersion int    `json:"guardVersion" validate:"gte=1"`
	// ExpiresAt is RFC 3339 UTC, whole seconds.
	ExpiresAt   string `json:"expiresAt" validate:"required"`
	Code        string `json:"code" validate:"required"`
	Fingerprint string `json:"fingerprint" validate:"required"`
}

// Expires parses ExpiresAt.
func (s Setup) Expires() (time.Time, error) {
	return time.Parse(time.RFC3339, s.ExpiresAt)
}

// Limits bound agent statements. Zero means the engine default.
type Limits struct {
	StatementTimeoutMs int `json:"statementTimeoutMs,omitempty" validate:"gte=0"`
	ReadRowLimit       int `json:"readRowLimit,omitempty" validate:"gte=0"`
}

// StatementTimeout is the configured time limit, or zero for the default.
func (l Limits) StatementTimeout() time.Duration {
	return time.Duration(l.StatementTimeoutMs) * time.Millisecond
}

// SocketPath is the socket the engine serves agent name on.
func (c Config) SocketPath(name string) string {
	return SocketPath(c.SocketDir, name)
}

// SocketPath is the socket for agent name in dir.
func SocketPath(dir, name string) string {
	return filepath.Join(dir, name+socketSuffix)
}

// maxSocketPath is the longest Unix socket path every supported platform
// binds: sockaddr_un.sun_path is 104 bytes on macOS (108 on Linux),
// including the terminating NUL.
const maxSocketPath = 103

// CheckSocketPath refuses a socket path too long to bind, which the kernel
// reports only as "invalid argument" when the engine starts.
func CheckSocketPath(path string) error {
	if len(path) > maxSocketPath {
		return fmt.Errorf("socket path %s is %d bytes; Unix sockets allow %d: choose a shorter socket directory",
			path, len(path), maxSocketPath)
	}
	return nil
}

// checkSocketPaths runs CheckSocketPath on every agent's socket.
func (c Config) checkSocketPaths() error {
	for _, a := range c.Agents {
		if err := CheckSocketPath(c.SocketPath(a.Name)); err != nil {
			return err
		}
	}
	return nil
}

var validate = newValidator()

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	if err := v.RegisterValidation("agentname", func(fl validator.FieldLevel) bool {
		return ValidAgentName(fl.Field().String())
	}); err != nil {
		panic(err)
	}
	return v
}

// ValidAgentName reports whether name is a valid agent name: the same rule
// the guard applies to role names (lowercase letters, digits and '_',
// starting with a letter, basalt_agent_<name> within 63 bytes), so a name
// the engine accepts is one basalt init can create a role for.
func ValidAgentName(name string) bool {
	return guard.ValidAgentName(name)
}

// Load reads and validates the config file at path. Unknown keys are refused.
func Load(path string) (Config, error) {
	raw, err := readSmall(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if err := validate.Struct(c); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if err := c.checkSocketPaths(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if _, err := c.Pages(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// ReadCredential reads an agent's Postgres URL. It refuses a file that group
// or others can read, so a credential never sits readable by the agent.
func ReadCredential(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&credentialPermMask != 0 {
		return "", fmt.Errorf("credential file %s is mode %o; it must be readable by the engine's user only (0600)", path, fi.Mode().Perm())
	}
	raw, err := readSmall(path)
	if err != nil {
		return "", err
	}
	url := strings.TrimSpace(string(raw))
	if url == "" {
		return "", fmt.Errorf("credential file %s is empty", path)
	}
	return url, nil
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) > maxConfigBytes {
		return nil, errors.New("file " + path + " is larger than 1 MiB")
	}
	return raw, nil
}
