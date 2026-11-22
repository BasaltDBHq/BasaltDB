package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
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

// perUserDirName is the per-user config directory under os.UserConfigDir.
const perUserDirName = config.UserDirName

// mcpBinary is the program of the printed basalt mcp command: the absolute,
// link-resolved path of the running binary, which the agent app finds
// whatever its PATH is. Bare basalt only when the path is unknown.
func mcpBinary(h host) string {
	if exe, err := h.Executable(); err == nil {
		return exe
	}
	return "basalt"
}

// temporaryBinaryWarning is a line to print after the mcp command when bin
// is in a folder that is often temporary (under tmp, or a Go build cache),
// else nothing. The command keeps the path; the person should move the
// binary somewhere that survives and register that path.
func temporaryBinaryWarning(bin, tmp string) string {
	// bin is link-resolved; resolve tmp too, or a tmp that is a link
	// (macOS /var -> /private/var) never matches.
	if resolved, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = resolved
	}
	rel, err := filepath.Rel(tmp, bin)
	underTmp := err == nil && rel != "." && !strings.HasPrefix(rel, "..")
	if !underTmp && !strings.Contains(filepath.ToSlash(bin), "/go-build") {
		return ""
	}
	return fmt.Sprintf("basalt: %s is in a folder that may be cleared; put the binary in a folder that survives and register that path instead\n", bin)
}

// mcpArgs is basalt mcp for the agent, with bin as the program. basalt mcp
// finds the engine config and the socket directory by itself.
func mcpArgs(agent, bin string) []string {
	return []string{bin, "mcp", "--agent", agent}
}

// shellJoin quotes each argument for display.
func shellJoin(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, shellQuote(a))
	}
	return strings.Join(out, " ")
}

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
func agentServiceSpec(goos, bin, configPath, engineUser string, a agentInstall, printOnly bool) (service.Spec, error) {
	spec := service.Spec{GOOS: goos, Binary: bin, ConfigPath: configPath, User: engineUser}
	cred := filepath.Join(filepath.Dir(configPath), "agents", a.name+".url")
	spec.Files = []service.File{{Path: configPath}}
	if !a.keepCredential {
		spec.Files = append(spec.Files, service.File{Path: cred})
	}
	if printOnly {
		return spec, nil
	}
	// Root reads the existing config from the engine user's directory.
	open := func(p string) (*os.File, error) { return openEngineFile(p, engineUser) }
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
func (a agentInstall) vaultChoice() vaultChoice {
	return vaultChoice{given: modeOf(a.vault), def: modeOf(a.vaultDefault), why: personDefaultWhy}
}

// Flags of basalt service install --agent that carry init's saved flags and
// say the credential file stays.
const (
	flagInitArg        = "init-arg"
	flagKeepCredential = "keep-credential"
	flagPersonUID      = "person-uid"
)

// dialogScript is the first install's fixed script for the running
// binary, with every link resolved and checked as root would run it.
func dialogScript(c *cliIO) (bin, script string, err error) {
	bin, err = c.host.ResolvedExecutable()
	if err != nil {
		return "", "", fmt.Errorf("the engine service runs this basalt binary by its own path, and its links do not resolve: %w", err)
	}
	if err := c.host.System(c.stderr, c.stderr).CheckBinary(bin); err != nil {
		return "", "", err
	}
	script, err = service.InstallScript(c.goos, bin)
	return bin, script, err
}

// dialogEngineArgs is the command the first install's unit runs.
func dialogEngineArgs(goos, bin string) []string {
	return []string{bin, "engine", "--config", config.DefaultPath(goos), "--supervise"}
}

// noDialog is init's stop when no administrator dialog can be shown: it
// never falls back to running the engine as the person's user.
func noDialog(err error) error {
	return fmt.Errorf("basalt init installs the engine service through the system's administrator dialog, which only you can answer, and it cannot be shown here (%w). "+
		"Run basalt init again in a desktop session on this machine; basalt does not run the engine as your user instead", err)
}

// darwinEngineLog is the engine service's log on macOS (the unit's
// StandardErrorPath).
const darwinEngineLog = "/Library/Logs/Basalt/engine.log"

func engineLogHint(goos string) string {
	if goos == "darwin" {
		return darwinEngineLog
	}
	return "journalctl -u " + service.SystemdUnitName
}

// envSudoUID is the uid of the user who ran sudo.
const envSudoUID = "SUDO_UID"

// invokingUID is the uid of the person running init.
func invokingUID(c *cliIO) (uint32, error) {
	euid := c.host.Euid()
	if euid != 0 {
		return uint32(euid), nil
	}
	sudo := c.getenv(envSudoUID)
	if sudo == "" {
		return 0, errNoPerson
	}
	return parseUID(sudo)
}

var errNoPerson = errors.New("no person to record (init runs as root without SUDO_UID); " +
	"give --person-uid N, the person's OS user id")

// checkPersons refuses no uid and root.
func checkPersons(uids []uint32) error {
	if len(uids) == 0 {
		return errNoPerson
	}
	for _, u := range uids {
		if u == 0 {
			return errors.New("--person-uid 0 is root; give the person's OS user id")
		}
	}
	return nil
}

// parseUID reads an OS user id.
func parseUID(v string) (uint32, error) {
	uid, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not an OS user id", v)
	}
	return uint32(uid), nil
}
