package setup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// basalt service install (CONTRACT.md, CLI): it installs the engine service
// and, with --agent, places the agent in the service's own directories, the
// engine config (the existing one with the agent upserted) and the
// credential, both owned by the engine's user. The steps are here; the
// files, the units and the OS users are reached through ServiceHost, which
// internal/app fills.

// ServiceInstaller runs basalt service install on Host, looking the OS users
// up through Users.
type ServiceInstaller struct {
	Host  ServiceHost
	Users Users
}

// ServiceInstall is one basalt service install as its flags gave it.
type ServiceInstall struct {
	GOOS, Binary, ConfigPath, User string
	DryRun, CredentialStdin        bool
	// SudoUID is the SUDO_UID environment variable, "" when unset: the
	// person when no --person-uid gives one.
	SudoUID string
	Agent   AgentInstall
}

// AgentInstall is the agent basalt service install places for the engine.
type AgentInstall struct {
	Name, OSUser, PagesURL, DSN string
	// Vault is the config's vault the person chose (config.VaultOn or
	// VaultOff); VaultDefault applies only when the config has none. Both
	// "" keep the config's.
	Vault, VaultDefault string
	// Report, when set, is told the vault the install wrote.
	Report func(config.VaultWritten)
	// InitArgs are what --init-arg gave: checked for a secret, never saved
	// (engine.json keeps no init flags).
	InitArgs []string
	// KeepCredential leaves the credential file as it is (the role kept its
	// password); DSN is empty.
	KeepCredential bool
	// Waiting: the agent has no credential file and waits for its
	// database's address (a connect-only setup code): nothing is written
	// for its credential, and its pending setup stays in the config.
	Waiting bool
	// PersonUIDs are added to the config's personUids.
	PersonUIDs []uint32
	// OperatedBy replaces the config's operatedBy when set (PERSON or AGENT).
	OperatedBy string
	// DevLocalPages is written with PagesURL (CONTRACT.md, Page origins).
	DevLocalPages bool
}

// VaultChoice is the init choice a service install carries: only basalt
// init, which is person-operated, runs it.
func (a AgentInstall) VaultChoice() VaultChoice {
	return VaultChoice{Given: ModeOf(a.Vault), Def: ModeOf(a.VaultDefault), Why: PersonDefaultWhy}
}

// Install runs in: the agent (with --agent) read from stdin, warnings and
// the vault line on errw, the install's steps on out. The config lock
// --agent takes is held until the units are installed and handed to the
// engine's user.
func (s ServiceInstaller) Install(ctx context.Context, in ServiceInstall, stdin io.Reader, out, errw io.Writer) error {
	spec := servicespec.Spec{GOOS: in.GOOS, Binary: in.Binary, ConfigPath: in.ConfigPath, User: in.User}
	// The unit's memory limits follow the installed config's
	// pii.maxMemoryMB (the default when there is none yet), so running
	// install again after raising it rewrites them.
	if cfg, err := s.Host.LoadConfigNoFollow(in.ConfigPath); err == nil {
		spec.MemoryMB = cfg.PIIOrDefault().MaxMemoryMB
	}
	// lock is the config lock basalt service install --agent holds.
	var lock *config.HeldLock
	if a := in.Agent; a.Name != "" {
		if a.DevLocalPages {
			_, _ = fmt.Fprintln(errw, "basalt: "+config.DevLocalPagesWarning)
		}
		if len(a.PersonUIDs) == 0 && in.SudoUID != "" {
			uid, err := ParseUID(in.SudoUID)
			if err != nil {
				return fmt.Errorf("%s: %w", EnvSudoUID, err)
			}
			a.PersonUIDs = []uint32{uid}
		}
		if !in.DryRun {
			a.Report = func(v config.VaultWritten) { _, _ = fmt.Fprint(errw, a.VaultChoice().Line(v)) }
			// Hold the config lock from reading engine.json until the new
			// one is in place, as every config writer does; the lock file
			// goes to the engine's user (CONTRACT.md, Lock files).
			held, err := s.Host.LockConfigAs(in.ConfigPath, s.Host.OSLookupUID(in.User))
			if err != nil {
				return err
			}
			defer held.Release()
			lock = &held
		}
		var err error
		spec, err = s.AgentSpec(stdin, spec, a, in.CredentialStdin, in.DryRun)
		if err != nil {
			return err
		}
	}
	if cfg, err := s.Host.LoadConfigNoFollow(in.ConfigPath); err == nil {
		// Every local plugin entry runs under its own unit and OS user:
		// install writes them all again.
		spec = s.Host.WithPluginUnits(spec, cfg, errw)
	} else if !errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintf(errw, "basalt: %s cannot be read, so plugin service units are left as they are\n", in.ConfigPath)
	}
	if err := s.Host.InstallUnits(ctx, spec, in.DryRun, out, errw); err != nil {
		return err
	}
	// The install may have just made the engine's user.
	if lock != nil {
		if err := lock.HandTo(s.Host.OSLookupUID(in.User)); err != nil {
			return fmt.Errorf("give %s.lock to %s: %w", in.ConfigPath, in.User, err)
		}
	}
	return nil
}

// AgentSpec is basalt service install --agent: the agent and its credential
// (one line on stdin, never an argument) go into the service's own
// directories, owned by the engine's user.
func (s ServiceInstaller) AgentSpec(stdin io.Reader, spec servicespec.Spec, a AgentInstall, credStdin, dryRun bool) (servicespec.Spec, error) {
	switch {
	case !config.ValidAgentName(a.Name):
		return spec, fmt.Errorf("agent name %q is not valid", a.Name)
	case a.OSUser == "":
		return spec, errors.New("--agent needs --os-user")
	case !credStdin && !a.KeepCredential:
		return spec, errors.New("--agent needs --credential-stdin; the credential never goes on the command line")
	}
	// Init's saved flags go into engine.json: hold them to what the engine
	// accepts (no connection URL, no password) before anything is written.
	cfgPath, err := filepath.Abs(spec.ConfigPath)
	if err != nil {
		return spec, err
	}
	if _, err := config.AgentCommands(a.Name, cfgPath, spec.GOOS, guidance.ServiceManager{}); err != nil {
		return spec, err
	}
	if err := RefuseSecretInitArgs(a.InitArgs); err != nil {
		return spec, fmt.Errorf("--init-arg: %w", err)
	}
	if _, err := s.Users.Lookup(a.OSUser); err != nil {
		return spec, fmt.Errorf("os user %q: %w", a.OSUser, err)
	}
	if err := s.Host.CheckAgentOSUser(a.OSUser, spec.User); err != nil {
		return spec, err
	}
	if err := CheckServicePersons(a.PersonUIDs, spec.User, s.Users); err != nil {
		return spec, err
	}
	if a.KeepCredential {
		return s.KeptCredentialSpec(spec, a, dryRun)
	}
	line, err := bufio.NewReader(io.LimitReader(stdin, servicespec.MaxCredentialBytes)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return spec, err
	}
	a.DSN = strings.TrimSpace(line)
	if a.DSN == "" && !dryRun {
		return spec, errors.New("no connection string on stdin")
	}
	return s.agentServiceSpec(spec.GOOS, spec.Binary, spec.ConfigPath, spec.User, a, dryRun)
}

// KeptCredentialSpec is the install when the agent's role kept its
// password: the existing credential file must exist. It is written back
// unchanged, so it is owned by the engine's user even when the user changed.
func (s ServiceInstaller) KeptCredentialSpec(spec servicespec.Spec, a AgentInstall, dryRun bool) (servicespec.Spec, error) {
	cred := filepath.Join(filepath.Dir(spec.ConfigPath), "agents", a.Name+".url")
	raw, err := s.Host.ReadKeptCredential(cred, spec.User)
	if err != nil && s.waitingForAddress(spec, a.Name, cred) {
		// A connect-only setup waits for its address: no credential yet,
		// and the engine writes it after the person's YES (CONTRACT.md,
		// Connect-only setup codes), with the password in .secret, which
		// must be the engine user's own for that.
		if _, serr := s.Host.ReadKeptCredential(config.SecretPath(cred, a.Name), spec.User); serr != nil && !dryRun {
			return spec, fmt.Errorf("agent %s waits for its database's address, but its .secret is not usable by the engine's user %s (%w); run basalt init --remote as that user", a.Name, spec.User, serr)
		}
		a.KeepCredential, a.Waiting = true, true
		return s.agentServiceSpec(spec.GOOS, spec.Binary, spec.ConfigPath, spec.User, a, dryRun)
	}
	if err != nil && !dryRun {
		return spec, fmt.Errorf("the agent's role keeps its password but its credential file %s is not usable (%w); run basalt init --rotate-password", cred, err)
	}
	a.DSN, a.KeepCredential = raw, false
	return s.agentServiceSpec(spec.GOOS, spec.Binary, spec.ConfigPath, spec.User, a, dryRun)
}

// waitingForAddress reports whether the config gives agent name a pending
// connect-only setup and no credential file exists at cred: the agent
// waits for its database's address.
func (s ServiceInstaller) waitingForAddress(spec servicespec.Spec, name, cred string) bool {
	cfg, err := s.Host.LoadEngineConfigAsSelf(spec.ConfigPath)
	if err != nil {
		return false
	}
	for _, ag := range cfg.Agents {
		if ag.Name == name && ag.Setup != nil && ag.Setup.ConnectOnly() {
			return s.Host.CredentialMissing(cred)
		}
	}
	return false
}

// agentServiceSpec is the service install spec with the agent's files in
// the service's own directories: the engine config (the existing one with
// the agent upserted) and the credential, both owned by the engine's user.
// For a plan that is only printed, contents are left out.
func (s ServiceInstaller) agentServiceSpec(goos, bin, configPath, engineUser string, a AgentInstall, printOnly bool) (servicespec.Spec, error) {
	spec := servicespec.Spec{GOOS: goos, Binary: bin, ConfigPath: configPath, User: engineUser}
	cred := filepath.Join(filepath.Dir(configPath), "agents", a.Name+".url")
	spec.Files = []servicespec.File{{Path: configPath}}
	if !a.KeepCredential {
		spec.Files = append(spec.Files, servicespec.File{Path: cred})
	}
	if printOnly {
		return spec, nil
	}
	// Root reads the existing config from the engine user's directory.
	raw, v, err := s.Host.UpsertedVault(configPath, engineUser,
		config.Settings{
			SocketDir: config.DefaultSocketDir(goos), PagesURL: a.PagesURL, DevLocalPages: a.DevLocalPages, Mode: config.ModeService, PersonUIDs: a.PersonUIDs,
			Vault: a.Vault, VaultDefault: a.VaultDefault, OperatedBy: a.OperatedBy, KeepConnectOnlySetup: a.Waiting,
		},
		config.Agent{Name: a.Name, OSUser: a.OSUser, Store: config.PostgresStore(cred)})
	if err != nil {
		return spec, err
	}
	if a.Report != nil {
		a.Report(v)
	}
	spec.Files[0].Content = raw
	// The unit's memory limits follow the config's pii.maxMemoryMB.
	var written config.Config
	if err := json.Unmarshal(raw, &written); err == nil {
		spec.MemoryMB = written.PIIOrDefault().MaxMemoryMB
	}
	if !a.KeepCredential {
		spec.Files[1].Content = []byte(a.DSN + "\n")
	}
	return spec, nil
}
