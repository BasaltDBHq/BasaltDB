package app

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

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// leakedAdmin is an admin connection string an agent was handed; no output
// may ever echo it. It is built from parts so no secret scanner reads it as
// a committed credential.
var leakedAdmin = "postgres://postgres" + ":" + "hunter2-admin" + "@" + "db.example.com:5432/app"

// envAdminURL is the name a person once set an admin connection string
// under; basalt reads nothing under it any more.
const envAdminURL = "BASALT_ADMIN_DATABASE_URL"

// TestInitRemoteIgnoresAnAdminEnv: init --remote never uses an admin
// connection string left in the environment and never echoes it.
func TestInitRemoteIgnoresAnAdminEnv(t *testing.T) {
	t.Parallel()
	r := cliOn(t, newFakeHost(t), map[string]string{envAdminURL: leakedAdmin}, "",
		"init", "--remote", "--agent", "bot", "--config", filepath.Join(t.TempDir(), "engine.json"))
	require.NotContains(t, r.stdout+r.stderr, "hunter2")
}

func TestTopLevelHelpHidesEngine(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	usage(&out)
	require.NotRegexp(t, `(?m)^\s+engine\s`, out.String())
	require.Regexp(t, `(?m)^\s+service\s`, out.String())

	// The command is hidden, not gone: it still parses its own flags.
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"engine", "--help"}, cli.Stdio{In: strings.NewReader(""), Out: &stdout, Err: &stderr})
	require.Equal(t, cli.ExitUsage, code)
	require.Contains(t, stderr.String(), "-config")
	require.NotContains(t, stderr.String(), "unknown command")
}

func TestTopLevelHelpTellsAgents(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	usage(&out)
	require.Contains(t, out.String(), cli.AgentsHelp)
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
	requireAgentLed(t, "MCP instructions", Instructions)
	for name, text := range map[string]string{
		"agentsHelp": cli.AgentsHelp,
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
		// format, not text an agent is told to follow.
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
	requireInternalStringsAgentLed(t, root)
}

// agentTextExcluded are the directories directly under internal/ whose
// strings never reach an agent, each with its reason. Every other non-test Go file under
// internal/ is scanned, so a new package is held without a list to keep.
// An exclusion whose strings would pass the check is stale and fails.
var agentTextExcluded = map[string]string{
	"internal/testkit": "test helpers: the step catalog's checks name the removed and manual flags they refuse",
}

// requireInternalStringsAgentLed checks the string literals of every
// non-test Go file under root's internal/ except agentTextExcluded.
func requireInternalStringsAgentLed(t *testing.T, root string) {
	t.Helper()
	internal := filepath.Join(root, "internal")
	entries, err := os.ReadDir(internal)
	require.NoError(t, err)
	scanned := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, skip := agentTextExcluded["internal/"+e.Name()]; skip {
			continue
		}
		requireGoStringsAgentLed(t, filepath.Join(internal, e.Name()))
		scanned++
	}
	require.Positive(t, scanned)
	for dir, reason := range agentTextExcluded {
		require.NotEmpty(t, strings.TrimSpace(reason), "agentTextExcluded[%s] needs a reason", dir)
		require.Positive(t, manualInitsInGoStrings(t, filepath.Join(root, filepath.FromSlash(dir))),
			"agentTextExcluded[%s] holds no string the check would refuse; remove the exclusion", dir)
	}
}

// manualInitsInGoStrings counts the string literals in the non-test Go files
// under dir that name a manual init.
func manualInitsInGoStrings(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	walkGoStrings(t, dir, func(_, s string) {
		if len(manualInits(s)) > 0 {
			n++
		}
	})
	return n
}

// requireGoStringsAgentLed checks every string literal in the non-test Go
// files under dir: the engine's errors, next steps and refusals reach the
// agent.
func requireGoStringsAgentLed(t *testing.T, dir string) {
	t.Helper()
	files := walkGoStrings(t, dir, func(p, s string) { requireAgentLed(t, p, s) })
	require.Positive(t, files, dir)
}

// walkGoStrings calls fn with each string literal in the non-test Go files
// under dir, and returns how many files it read.
func walkGoStrings(t *testing.T, dir string, fn func(path, s string)) int {
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
			fn(p, s)
			return true
		})
		return nil
	}))
	return files
}
