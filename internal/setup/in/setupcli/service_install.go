package setupcli

import (
	"context"
	"errors"
	"os"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// Flags of basalt service install --agent that carry init's choices and say
// the credential file stays.
const (
	flagVault          = "vault"
	flagVaultDefault   = "vault-default"
	flagDevLocalPages  = "dev-local-pages"
	flagInitArg        = "init-arg"
	flagKeepCredential = "keep-credential" //nolint:gosec // a flag name, not a credential
	flagPersonUID      = "person-uid"
)

// RunServiceInstall is basalt service on the engine config at configPath
// (the service's engine always runs on the system path; tests give their
// own): it reads the flags of install and runs it on h, looking OS users up
// through users. A refused command line exits 2, any other error 1.
func RunServiceInstall(ctx context.Context, args []string, io cli.Stdio, configPath string, h setup.ServiceHost, users setup.Users) int {
	if len(args) == 0 || args[0] != "install" {
		cli.Fail(io.Err, "service", errors.New("want install"))
		return cli.ExitUsage
	}
	fs := cli.NewFlagSet("service " + args[0])
	fs.SetOutput(io.Err)
	user := fs.String("user", h.OSDefaultUser(runtime.GOOS), "OS user the engine runs as")
	binary := fs.String("binary", "", "absolute path of the basalt binary (default: this binary)")
	dryRun := fs.Bool("dry-run", false, "print the steps without running them")
	var a setup.AgentInstall
	fs.StringVar(&a.Name, "agent", "", "install: also place this agent (basalt init runs this under sudo)")
	fs.StringVar(&a.OSUser, "os-user", "", "install --agent: the agent's OS user")
	fs.Func("pages-url", "install --agent: the pages base URL the agent's passkey belongs to", func(v string) error {
		if err := config.CheckPagesURL("--pages-url", v); err != nil {
			return err
		}
		a.PagesURL = v
		return nil
	})
	fs.BoolVar(&a.DevLocalPages, flagDevLocalPages, false, "install --agent: the config's devLocalPages, as basalt init --dev-local-pages sets it")
	fs.Func(flagVault, "install --agent: on or off, the config's vault as the person chose it (default: keep the config's)", func(v string) error {
		var m setup.VaultMode
		if err := m.Set(v); err != nil {
			return err
		}
		a.Vault = m.Enum()
		return nil
	})
	fs.Func(flagVaultDefault, "install --agent: on or off, the config's vault only when it has none yet", func(v string) error {
		var m setup.VaultMode
		if err := m.Set(v); err != nil {
			return err
		}
		a.VaultDefault = m.Enum()
		return nil
	})
	fs.Func("operated-by", "install --agent: person or agent, the config's operatedBy (default: keep the config's)", func(v string) error {
		var o setup.OperatedBy
		if err := o.Set(v); err != nil {
			return err
		}
		a.OperatedBy = o.Enum()
		return nil
	})
	fs.Func(flagInitArg, "install --agent: ignored, kept for older install scripts; refused when it holds a secret (repeatable)", func(v string) error {
		a.InitArgs = append(a.InitArgs, v)
		return nil
	})
	fs.Func(flagPersonUID, "install --agent: an OS user id of the person (repeatable; default: SUDO_UID)", func(v string) error {
		uid, err := setup.ParseUID(v)
		if err != nil {
			return err
		}
		a.PersonUIDs = append(a.PersonUIDs, uid)
		return nil
	})
	fs.BoolVar(&a.KeepCredential, flagKeepCredential, false, "install --agent: keep the agent's credential file (its role kept its password)")
	credStdin := fs.Bool("credential-stdin", false, "install --agent: read the agent's connection string from stdin")
	if fs.Parse(args[1:]) != nil || fs.NArg() > 0 {
		return cli.ExitUsage
	}
	if a.KeepCredential && *credStdin {
		cli.Fail(io.Err, "service", errors.New("--keep-credential and --credential-stdin cannot be used together"))
		return cli.ExitUsage
	}
	bin, err := cli.BinaryPath(*binary)
	if err != nil {
		return cli.Fail(io.Err, "service", err)
	}
	in := setup.ServiceInstall{
		GOOS: runtime.GOOS, Binary: bin, ConfigPath: configPath, User: *user,
		DryRun: *dryRun, CredentialStdin: *credStdin, SudoUID: os.Getenv(setup.EnvSudoUID), Agent: a,
	}
	if err := (setup.ServiceInstaller{Host: h, Users: users}).Install(ctx, in, io.In, io.Out, io.Err); err != nil {
		return cli.Fail(io.Err, "service", err)
	}
	return cli.ExitOK
}
