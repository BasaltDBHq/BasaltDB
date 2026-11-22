package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// leakedAdmin is an admin connection string an agent was handed; no output
// may ever echo it. It is built from parts so no secret scanner reads it as
// a committed credential.
var leakedAdmin = "postgres://postgres" + ":" + "hunter2-admin" + "@" + "db.example.com:5432/app"

// TestAgentContextRefusesTheAdminCredential: under an agent, every command
// that takes the admin connection string refuses before reading it, from
// the environment or stdin, and never echoes it.
func TestAgentContextRefusesTheAdminCredential(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"setup code", []string{"init", "--setup-code", "basalt-setup.1.x.y", "--yes"}, "Give the person this command instead of running it"},
	}
	for _, marker := range agentMarkers {
		for _, tc := range cases {
			t.Run(marker+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				r := cliOn(t, newFakeHost(t), map[string]string{marker: "1"}, leakedAdmin+"\n", tc.args...)
				require.Equal(t, exitError, r.code, r.stderr)
				require.Contains(t, r.stderr, "it is running under an agent ("+marker+" is set)")
				require.Contains(t, r.stderr, "An agent never asks for, accepts or types the admin connection string or password.")
				require.Contains(t, r.stderr, tc.want)
				require.NotContains(t, r.stderr, "Admin connection string (used once", "no prompt under an agent")
				require.NotContains(t, r.stderr, "change that database password", "nothing leaked through the environment")
				require.NotContains(t, r.stdout+r.stderr, "hunter2")
			})
		}
	}
}

// TestAgentContextAdminEnvSaysRotate: an admin connection string in the
// agent's environment is not used, and the person is told to change it.
func TestAgentContextAdminEnvSaysRotate(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"init", "--setup-code", "basalt-setup.1.x.y"},
	} {
		t.Run(args[0]+" "+args[1], func(t *testing.T) {
			t.Parallel()
			r := cliOn(t, newFakeHost(t), map[string]string{"CLAUDECODE": "1", envAdminURL: leakedAdmin}, "", args...)
			require.Equal(t, exitError, r.code, r.stderr)
			require.NotContains(t, r.stdout+r.stderr, "hunter2")
			if args[0] == "init" {
				require.Contains(t, r.stderr, adminEnvLeaked)
			}
		})
	}
}

// TestAgentContextNeedsAMarker: without a marker, a person's command reads
// the admin credential as before (here from the environment, then fails to
// connect to a database that is not there).
func TestAgentContextNeedsAMarker(t *testing.T) {
	t.Parallel()
	c := &cliIO{getenv: func(k string) string {
		if k == envAdminURL {
			return leakedAdmin
		}
		return ""
	}}
	require.Empty(t, c.agentMarker())
	got, err := c.adminURL()
	require.NoError(t, err)
	require.Equal(t, leakedAdmin, got)

	c.getenv = func(k string) string {
		if k == "CLAUDECODE" {
			return "  "
		}
		return ""
	}
	require.Empty(t, c.agentMarker(), "a blank value is not a marker")
}

// TestInitRemoteWarnsAboutAnAdminEnv: init --remote never uses
// BASALT_ADMIN_DATABASE_URL and says to change that password.
func TestInitRemoteWarnsAboutAnAdminEnv(t *testing.T) {
	t.Parallel()
	r := cliOn(t, newFakeHost(t), map[string]string{envAdminURL: leakedAdmin}, "",
		"init", "--remote", "--agent", "bot", "--config", filepath.Join(t.TempDir(), "engine.json"))
	require.Contains(t, r.stderr, remoteAdminEnvSet)
	require.NotContains(t, r.stdout+r.stderr, "hunter2")
}

func TestAgentNotInConfigNamesTheAgentLedSetup(t *testing.T) {
	t.Parallel()
	err := errAgentNotInConfig("bot", "/etc/basalt/engine.json")
	require.EqualError(t, err, `agent "bot" is not in /etc/basalt/engine.json; set it up with basalt init --remote --agent bot and give the person the setup code it prints`)
	requireAgentLed(t, "errAgentNotInConfig", err.Error())
}

func TestTopLevelHelpTellsAgents(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	usage(&out)
	require.Contains(t, out.String(), agentsHelp)
	requireAgentLed(t, "basalt --help", out.String())
}

// initCommand finds each basalt init command in a text, up to the end of its
// line or the quote, backtick or sentence that holds it. A shell line
// continuation (backslash, newline) joins the next line.
var initCommand = regexp.MustCompile("(?:basalt\\s+)?\\binit(?:\\s+-[^\\n`\"';]*?)?(?:\\n|`|\"|'|;|\\.\\s|\\.$|$)")

// manualInits are the basalt init commands in text that name --agent
// without --remote (or --setup-code): an agent that runs one has to ask the
// person for the admin password.
func manualInits(text string) []string {
	text = strings.ReplaceAll(text, "\\\n", " ")
	var out []string
	for _, m := range initCommand.FindAllString(text, -1) {
		if strings.Contains(m, "--agent") && !strings.Contains(m, "--remote") && !strings.Contains(m, "--setup-code") {
			out = append(out, strings.TrimSpace(m))
		}
	}
	return out
}

// requireAgentLed fails when text recommends basalt init with --agent and
// without --remote to an agent.
func requireAgentLed(t *testing.T, where, text string) {
	t.Helper()
	for _, m := range manualInits(text) {
		t.Errorf("%s recommends %q to an agent: agents only run basalt init --remote", where, m)
	}
}

func TestManualInitsCatchesTheManualCommand(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"run basalt init --agent bot --write public.leads",
		"or set that user with basalt init --agent bot --os-user <user>",
		"Run `basalt init --agent NAME --write schema.table` now.",
		"run basalt init --write public.leads --agent bot; then start it",
	} {
		require.NotEmpty(t, manualInits(text), text)
	}
	for _, text := range []string{
		"run basalt init --remote --agent bot --write public.leads",
		"basalt init --remote --operated-by=agent --vault=off \\\n  --agent NAME --write schema.table",
		"basalt init --setup-code basalt-setup.1.x.y",
		"Use basalt init for that. The agent is --agent bot.",
		"initArgs --agent bot",
	} {
		require.Empty(t, manualInits(text), text)
	}
}

// TestAgentFacingTextIsAgentLed greps every surface an agent reads: the MCP
// instructions, tool schemas and next steps, the engine's own strings, the
// agent docs and basalt's agent help. None may steer an agent to basalt init
// without --remote.
func TestAgentFacingTextIsAgentLed(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	requireAgentLed(t, "MCP instructions", engine.Instructions)
	for name, text := range map[string]string{
		"agentsHelp":         agentsHelp,
		"hintAgentSetupCode": hintAgentSetupCode, "hintAgentPerson": hintAgentPerson,
		"adminEnvLeaked": adminEnvLeaked, "remoteAdminEnvSet": remoteAdminEnvSet,
	} {
		requireAgentLed(t, name, text)
	}
	for _, doc := range []string{"llms.txt", filepath.Join("docs", "bot-setup.md")} {
		raw, err := os.ReadFile(filepath.Join(root, doc))
		require.NoError(t, err)
		requireAgentLed(t, doc, string(raw))
	}
	jsonFiles := 0
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "api", "mcp"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		jsonFiles++
		// JSON strings: unescape the common escapes so a command reads as text.
		requireAgentLed(t, p, strings.NewReplacer(`\"`, `"`, `\n`, "\n").Replace(string(raw)))
		return nil
	}))
	require.Positive(t, jsonFiles)
	for _, dir := range []string{"engine", "mcp", "shim"} {
		requireGoStringsAgentLed(t, filepath.Join(root, "internal", dir))
	}
}

// requireGoStringsAgentLed checks every string literal in the non-test Go
// files under dir: the engine's errors, next steps and refusals reach the
// agent.
func requireGoStringsAgentLed(t *testing.T, dir string) {
	t.Helper()
	files := 0
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".go" || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true // not a Go string after all; nothing to check
			}
			requireAgentLed(t, p, s)
			return true
		})
		return nil
	}))
	require.Positive(t, files, dir)
}
