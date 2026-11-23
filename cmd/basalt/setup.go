package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/setup"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// After the guard and the passkey, basalt init sets up the engine one of
// two ways, decided once:
//
//   - as a background service under its own OS user (the default, asked
//     at the terminal): one sudo elevation runs basalt service install
//     with the agent, which writes the config and the credential into the
//     service's system directories owned by that user, installs and
//     starts the unit; init then checks the engine answers on the socket.
//   - in the foreground as the person (--no-service, an answer of no, or
//     the engine config found in the person's own config directory):
//     init writes the config and credential where the person can, and
//     prints the one command.
//
// Without a terminal, --yes or --no-service must say which: init never
// falls back to the foreground on its own (checkServiceAnswer).

// agentInstall is the agent basalt service install places for the engine.
type agentInstall struct {
	name, osUser, pagesURL, dsn string
	// vault is the config's vault the person chose (config.VaultOn or
	// VaultOff); vaultDefault applies only when the config has none. Both
	// "" keep the config's.
	vault, vaultDefault string
	// report, when set, is told the vault the install wrote.
	report func(config.VaultWritten)
	// initArgs are what --init-arg gave: checked for a secret, never saved
	// (engine.json keeps no init flags).
	initArgs []string
	// keepCredential leaves the credential file as it is (the role kept its
	// password); dsn is empty.
	keepCredential bool
	// waiting: the agent has no credential file and waits for its
	// database's address (a connect-only setup code): nothing is written
	// for its credential, and its pending setup stays in the config.
	waiting bool
	// personUIDs are added to the config's personUids.
	personUIDs []uint32
	// operatedBy replaces the config's operatedBy when set (PERSON or AGENT).
	operatedBy string
	// devLocalPages is written with pagesURL (CONTRACT.md, Page origins).
	devLocalPages bool
}

// agentServiceSpec is the service install spec with the agent's files in
// the service's own directories: the engine config (the existing one with
// the agent upserted) and the credential, both owned by the engine's user.
// For a plan that is only printed, contents are left out.
func agentServiceSpec(goos, bin, configPath, engineUser string, a agentInstall, printOnly bool) (app.OSSpec, error) {
	spec := app.OSSpec{GOOS: goos, Binary: bin, ConfigPath: configPath, User: engineUser}
	cred := filepath.Join(filepath.Dir(configPath), "agents", a.name+".url")
	spec.Files = []app.OSFile{{Path: configPath}}
	if !a.keepCredential {
		spec.Files = append(spec.Files, app.OSFile{Path: cred})
	}
	if printOnly {
		return spec, nil
	}
	// Root reads the existing config from the engine user's directory.
	open := func(p string) (*os.File, error) { return app.OpenEngineFile(appSetupHost{}, p, engineUser) }
	raw, v, err := config.UpsertedVault(configPath, open,
		config.Settings{
			SocketDir: config.DefaultSocketDir(goos), PagesURL: a.pagesURL, DevLocalPages: a.devLocalPages, Mode: config.ModeService, PersonUIDs: a.personUIDs,
			Vault: a.vault, VaultDefault: a.vaultDefault, OperatedBy: a.operatedBy, KeepConnectOnlySetup: a.waiting,
		},
		config.Agent{Name: a.name, OSUser: a.osUser, Store: config.PostgresStore(cred)})
	if err != nil {
		return spec, err
	}
	if a.report != nil {
		a.report(v)
	}
	spec.Files[0].Content = raw
	// The unit's memory limits follow the config's pii.maxMemoryMB.
	var written config.Config
	if err := json.Unmarshal(raw, &written); err == nil {
		spec.MemoryMB = written.PIIOrDefault().MaxMemoryMB
	}
	if !a.keepCredential {
		spec.Files[1].Content = []byte(a.dsn + "\n")
	}
	return spec, nil
}

// vaultChoice is the init choice a service install carries: only basalt
// init, which is person-operated, runs it.
func (a agentInstall) vaultChoice() setup.VaultChoice {
	return setup.VaultChoice{Given: setup.ModeOf(a.vault), Def: setup.ModeOf(a.vaultDefault), Why: setup.PersonDefaultWhy}
}

// Flags of basalt service install --agent that carry init's saved flags and
// say the credential file stays.
const (
	flagInitArg        = "init-arg"
	flagKeepCredential = "keep-credential"
	flagPersonUID      = "person-uid"
)
