package main

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app"
)

// leakedAdmin is an admin connection string an agent was handed; no output
// may ever echo it. It is built from parts so no secret scanner reads it as
// a committed credential.
var leakedAdmin = "postgres://postgres" + ":" + "hunter2-admin" + "@" + "db.example.com:5432/app"

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
	require.EqualError(t, err, `agent "bot" is not in /etc/basalt/engine.json; set it up with basalt init --agent bot on the person's own computer, or basalt init --remote --agent bot on one the person cannot reach, and show the person the link it prints`)
	requireAgentLed(t, "errAgentNotInConfig", err.Error())
}

func TestTopLevelHelpHidesEngine(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	usage(&out)
	require.NotRegexp(t, `(?m)^\s+engine\s`, out.String())
	require.Regexp(t, `(?m)^\s+service\s`, out.String())

	// The command is hidden, not gone: it still parses its own flags.
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"engine", "--help"}, stdio{in: strings.NewReader(""), out: &stdout, err: &stderr})
	require.Equal(t, exitUsage, code)
	require.Contains(t, stderr.String(), "-config")
	require.NotContains(t, stderr.String(), "unknown command")
}

func TestTopLevelHelpTellsAgents(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	usage(&out)
	require.Contains(t, out.String(), agentsHelp)
	requireAgentLed(t, "basalt --help", out.String())
}

// manualInits are the names in text of the ways to hand the admin connection
// string to basalt outside a setup page: the --setup-code and --database-url
// flags and the BASALT_ADMIN_DATABASE_URL= assignment. An agent told to use
// one has to ask the person for the admin password. Plain basalt init (the
// person's own computer) and basalt init --remote (one the person cannot
// reach) are what an agent runs, and are fine. It is a plain substring check,
// so a flag on the next line or after "with" is caught too.
func manualInits(text string) []string {
	var out []string
	for _, bad := range []string{"--setup-code", "--database-url", envAdminURL + "="} {
		if strings.Contains(text, bad) {
			out = append(out, bad)
		}
	}
	return out
}

// requireAgentLed fails when text recommends a basalt init that needs the
// admin connection string outside the setup page.
func requireAgentLed(t *testing.T, where, text string) {
	t.Helper()
	for _, m := range manualInits(text) {
		t.Errorf("%s recommends %q to an agent: the admin connection string is typed only on a setup page", where, m)
	}
}

func TestManualInitsCatchesTheManualCommand(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"run basalt init --setup-code basalt-setup.1.x.y",
		"or run basalt init --agent bot --database-url postgres://h/db",
		"Run `basalt init` with --setup-code now.",
		"basalt init \\\n  --database-url postgres://h/db",
		"export BASALT_ADMIN_DATABASE_URL=postgres://h/db and run basalt init",
	} {
		require.NotEmpty(t, manualInits(text), text)
	}
	for _, text := range []string{
		"run basalt init --remote --agent bot",
		"run basalt init --agent bot on the person's own computer",
		"Use basalt init for that. The agent is --agent bot.",
		"BASALT_ADMIN_DATABASE_URL is set where an agent can read it",
	} {
		require.Empty(t, manualInits(text), text)
	}
}

// TestAgentFacingTextIsAgentLed greps every surface an agent reads: the MCP
// instructions, tool schemas and next steps, the engine's own strings, the
// agent docs and basalt's agent help. None may steer an agent to a basalt
// init that takes the admin string anywhere but a setup page.
func TestAgentFacingTextIsAgentLed(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	requireAgentLed(t, "MCP instructions", app.Instructions)
	for name, text := range map[string]string{
		"agentsHelp":        agentsHelp,
		"remoteAdminEnvSet": remoteAdminEnvSet,
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
		// The setup code's own schema and fixtures describe the code's
		// format, not text an agent is told to follow; they go with
		// --setup-code.
		if filepath.Base(filepath.Dir(p)) == "setup" {
			return nil
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
	for _, dir := range []string{"internal/app", "internal/service/agent", "internal/config", "internal/service/handoff", "internal/service/pluginhost", "internal/service/person", "internal/service/piidict", "internal/service/portalcheck", "internal/service/upkeep", "internal/adapter/inbound/pages", "internal/adapter/outbound/osservice", "internal/lib/peercred", "internal/adapter/inbound/mcp", "internal/adapter/inbound/shim", "internal/approval/in/approvalpage", "internal/revert/in/revertpage", "internal/plugin/in/pluginpage"} {
		requireGoStringsAgentLed(t, filepath.Join(root, filepath.FromSlash(dir)))
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
