package agent

import (
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

var urlUserInfo = regexp.MustCompile(`://[^/\s]*@`)

// allCommands renders every command c can give.
func allCommands(c Commands) map[string]string {
	id := uuid.Must(uuid.NewV7())
	return map[string]string{
		"approve":       c.Approve(id),
		"revert":        c.Revert(action.Scope{Kind: revert.ScopeRun, ID: id}),
		"revertStatus":  c.RevertStatus(id),
		"passkeyList":   c.PasskeyList(),
		"upgrade":       c.Upgrade(),
		"init":          c.Init("--add-passkey"),
		"engineStart":   c.EngineStart(),
		"engineRestart": c.EngineRestart(),
	}
}

func TestCommandsConfigFlagOnlyOffDefault(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		def := config.DefaultPath(goos)
		for name, cmd := range allCommands(mustCommands(t, def, goos, nil)) {
			require.NotContains(t, cmd, "--config", "%s on %s: the default path is found by the CLI itself", name, goos)
			if strings.HasPrefix(cmd, "basalt ") {
				require.Contains(t, cmd, "--agent bot", name)
			}
		}
		for name, cmd := range allCommands(mustCommands(t, "", goos, nil)) {
			require.NotContains(t, cmd, "--config", name)
		}
		for name, cmd := range allCommands(mustCommands(t, "/home/me/engine.json", goos, nil)) {
			if strings.HasPrefix(cmd, "basalt ") {
				require.Contains(t, cmd, "--agent bot --config /home/me/engine.json", name)
			}
		}
	}
}

func TestCommandsDefaultPathIsPerPlatform(t *testing.T) {
	t.Parallel()
	linuxDefault := mustCommands(t, config.DefaultPath("linux"), "darwin", nil)
	require.Contains(t, linuxDefault.PasskeyList(), "--config /etc/basalt/engine.json",
		"the Linux default is not the macOS default")
}

func TestCommandsQuoteAConfigPathWithSpaces(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "/home/me/my cfg/engine.json", "linux", nil)
	require.Equal(t, "basalt passkey list --agent bot --config '/home/me/my cfg/engine.json'", c.PasskeyList())
}

func TestCommandsRefuseARelativeConfigPath(t *testing.T) {
	t.Parallel()
	_, err := NewCommands("bot", "engine.json", "linux", nil)
	require.Error(t, err)
}

func TestCommandShapes(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "/x/engine.json", "linux", []string{"--write", "public.leads", "--agent-rls", "all-rows"})
	id := uuid.MustParse("0198a5c4-0000-7000-8000-000000000001")
	cfg := "--agent bot --config /x/engine.json"
	require.Equal(t, "basalt approve "+cfg+" --open "+id.String(), c.Approve(id))
	require.Equal(t, "basalt revert "+cfg+" --run "+id.String()+" --open", c.Revert(action.Scope{Kind: revert.ScopeRun, ID: id}))
	require.Equal(t, "basalt revert "+cfg+" --status "+id.String(), c.RevertStatus(id))
	require.Equal(t, "basalt passkey list "+cfg, c.PasskeyList())
	require.Equal(t, "basalt upgrade "+cfg, c.Upgrade())
	require.Equal(t, "basalt init "+cfg+" --write public.leads --agent-rls all-rows --rotate-password", c.Init("--rotate-password"))
	require.Equal(t, "sudo systemctl start basalt-engine.service", c.EngineStart())
	require.Equal(t, "sudo systemctl restart basalt-engine.service", c.EngineRestart())

	mac := mustCommands(t, "", "darwin", nil)
	require.Equal(t, "sudo launchctl kickstart -k system/dev.basaltdb.engine", mac.EngineRestart())
	require.Equal(t, "sudo launchctl bootstrap system /Library/LaunchDaemons/dev.basaltdb.engine.plist; "+
		"sudo launchctl kickstart -k system/dev.basaltdb.engine", mac.EngineStart(), "works for an unloaded job")
}

func TestCommandsNeverCarryACredentialValue(t *testing.T) {
	t.Parallel()
	const secret = "hunter2"
	// The credential file's path is not a secret (AE-15): it may appear.
	c := mustCommands(t, "/x/engine.json", "linux",
		[]string{"--write", "public.leads", "--credential-file", "/etc/basalt/agents/bot.cred"})
	for name, cmd := range allCommands(c) {
		require.False(t, urlUserInfo.MatchString(cmd), "%s: %s", name, cmd)
		require.NotContains(t, cmd, "://", name)
		require.NotContains(t, strings.ReplaceAll(strings.ToLower(cmd), "--rotate-password", ""), "password", name)
	}
	require.Contains(t, c.Init("--add-passkey"), "--credential-file /etc/basalt/agents/bot.cred")

	// A credential value fed through any input never reaches a command.
	for _, args := range [][]string{
		{"--write", "postgres://admin:" + secret + "@db.example.com/app"},
		{"--write=postgres://admin:" + secret + "@db"},
		{"--prefix", "host=db password=" + secret},
		{"--credential-file", "postgres://u:" + secret + "@h/d"},
		{"-password", secret},
		{"--admin-url", secret},
		{secret},
	} {
		hostile, err := NewCommands("bot", "/x/engine.json", "linux", args)
		if err != nil {
			continue
		}
		for name, cmd := range allCommands(hostile) {
			require.NotContains(t, cmd, secret, "%v: %s", args, name)
		}
	}
}

func TestCommandsAllowOnlyTheFlagsInitSaves(t *testing.T) {
	t.Parallel()
	for _, ok := range [][]string{
		{"--write", "public.leads"},
		{"-write", "public.leads"},
		{"--write=public.leads"},
		{"-write=public.leads"},
		{"--agent", "bot", "--agent-rls", "all-rows", "--operated-by=person"},
		{"--credential-file", "/etc/basalt/agents/bot.cred"},
		{
			"--statement-timeout", "5s", "--engine-user", "basalt", "--os-user", "me", "--socket-dir", "/run/basalt",
			"--passkey-origin", "http://localhost:8787", "--prefix", "basalt", "--read", "public.a",
		},
	} {
		_, err := NewCommands("bot", "", "linux", ok)
		require.NoError(t, err, "%v", ok)
	}
	for _, bad := range [][]string{
		{"--admin-url", "x"},
		{"-password", "x"},
		{"--password=x"},
		{"--yes"},
		{"--dry-run"},
		{"--rotate-password"},
		{"--write"},
		{"public.leads"},
		{"--passkey-origin", "https://u:p@host"},
		{"--prefix", "http://x"},
		{"--write", "postgres://u:p@h/d"},
		{"--write=host=h password=x"},
		{"--agent", "other"},
		{"--config", "/x"},
	} {
		_, err := NewCommands("bot", "", "linux", bad)
		require.Error(t, err, "%v", bad)
	}
}

func TestCommandsRefuseABadAgentName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "Bot", "bot; rm -rf /", "a b", "$(x)"} {
		_, err := NewCommands(name, "", "linux", nil)
		require.Error(t, err, name)
	}
}

func TestCommandsQuoteALeadingEquals(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "", "linux", []string{"--write", "=ls"})
	require.Equal(t, "basalt init --agent bot --write '=ls' --add-passkey", c.Init("--add-passkey"), "zsh expands =cmd")
}

func TestInitDoesNotRepeatAgent(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "/x/engine.json", "linux", []string{"--agent", "bot", "--write", "public.leads"})
	require.Equal(t, "basalt init --config /x/engine.json --agent bot --write public.leads --add-passkey", c.Init("--add-passkey"))
	require.Equal(t, 1, strings.Count(c.Init("--add-passkey"), "--agent"))
}

func TestForegroundEngineCommands(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "/home/me/engine.json", "linux", nil).Foreground()
	require.Equal(t, "basalt engine --config /home/me/engine.json", c.EngineStart())
	require.Equal(t, "basalt engine --config /home/me/engine.json", c.EngineRestart())
	def := mustCommands(t, "", "darwin", nil).Foreground()
	require.Equal(t, "basalt engine --config "+shellQuote(config.DefaultPath("darwin")), def.EngineStart())
}

func mustCommands(t *testing.T, path, goos string, initArgs []string) Commands {
	t.Helper()
	c, err := NewCommands("bot", path, goos, initArgs)
	require.NoError(t, err)
	return c
}

func TestGrantExtendsTheSavedList(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		initArgs []string
		want     string
	}{
		"joined":   {[]string{"--agent=bot", "--read=public.a"}, "--read=public.a,public.t"},
		"separate": {[]string{"--agent", "bot", "--read", "public.a"}, "--read public.a,public.t"},
		"absent":   {[]string{"--agent=bot", "--write=public.w"}, "--write=public.w --read=public.t"},
	} {
		c, err := NewCommands("bot", "", "linux", tc.initArgs)
		require.NoError(t, err, name)
		got, err := c.Grant("read", "public.t")
		require.NoError(t, err, name)
		require.Contains(t, strings.ReplaceAll(got, "'", ""), tc.want, name)
	}
	c, err := NewCommands("bot", "", "linux", nil)
	require.NoError(t, err)
	for _, bad := range []string{"a,b", "public.a,public.b", "events", `"a b".c`, "public.a;rm", ""} {
		_, err := c.Grant("write", bad)
		require.ErrorIs(t, err, ErrBadTable, bad)
	}
}

// InitRemote keeps only the saved flags basalt init --remote takes (it
// refuses --os-user and init's other flags), and on an agent-operated
// engine asks for --json, whose steps the agent follows.
func TestInitRemoteKeepsTheFlagsItTakes(t *testing.T) {
	t.Parallel()
	c := mustCommands(t, "/srv/basalt/engine.json", "linux",
		[]string{"--agent=bot", "--write=public.leads", "--os-user", "bot", "--socket-dir=/run/b", "--read", "public.companies", "--operated-by=agent"})
	const saved = "--agent=bot --write=public.leads --read public.companies --operated-by=agent"
	require.Equal(t, "basalt init --remote --config /srv/basalt/engine.json "+saved+" --new-code", c.InitRemote("--new-code"))
	agentOperated := c.OperatedBy("AGENT")
	require.True(t, agentOperated.AgentOperated())
	require.Equal(t, "basalt init --remote --config /srv/basalt/engine.json "+saved+" --json", agentOperated.InitRemote(""))
	grant, err := agentOperated.RemoteGrant("write", "public.notes")
	require.NoError(t, err)
	require.Equal(t, "basalt init --remote --config /srv/basalt/engine.json --agent=bot '--write=public.leads,public.notes' "+
		"--read public.companies --operated-by=agent --json", grant)
	require.Equal(t, "basalt init --setup-code basalt-setup.1.abc.def", SetupCode("basalt-setup.1.abc.def"))
	require.False(t, c.OperatedBy("PERSON").AgentOperated())
}
