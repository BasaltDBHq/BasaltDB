package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// The surface budget (contract/surface.json): every command, flag, MCP
// tool and argument, environment variable and page path the product has.
// TestSurfaceBudget builds the real surface from the binary and the page
// tree and fails on any difference with the file, in either direction. An
// entry marked "removing" is still on the branch and names the epic that
// removes it; the epic's last change deletes the entry.

const surfacePath = "../../contract/surface.json"

type surfaceEntry struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
	Epic   string `json:"epic,omitempty"`
	SetBy  string `json:"setBy,omitempty"`
}

type surfaceFile struct {
	Version int            `json:"version"`
	About   string         `json:"about"`
	Entries []surfaceEntry `json:"entries"`
}

func (e surfaceEntry) key() string { return e.Kind + " " + e.Name }

func loadSurface(t *testing.T) surfaceFile {
	t.Helper()
	raw, err := os.ReadFile(surfacePath)
	if err != nil {
		t.Fatalf("read the surface budget: %v", err)
	}
	var f surfaceFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("decode %s: %v", surfacePath, err)
	}
	return f
}

// subcommandsOf reads the subcommands a command's summary lists in its last
// parentheses: "(list | add | revoke <id>)". Words that start with "-" are
// flags, not subcommands.
func subcommandsOf(summary string) []string {
	open := strings.LastIndex(summary, "(")
	end := strings.LastIndex(summary, ")")
	if open < 0 || end < open {
		return nil
	}
	inner := strings.TrimPrefix(summary[open+1:end], "or ")
	var subs []string
	for _, part := range strings.Split(inner, "|") {
		words := strings.Fields(part)
		if len(words) == 0 || strings.HasPrefix(words[0], "-") {
			continue
		}
		subs = append(subs, words[0])
	}
	return subs
}

// commandKey is the command a flag set belongs to: the set of "init
// --remote" holds flags of the command "init".
func commandKey(setName string) string {
	name, _, _ := strings.Cut(setName, " --")
	return name
}

// probeFlags runs the command line args with -h and returns every flag set
// the command made, by command key. -h stops the command at flag parsing.
func probeFlags(t *testing.T, run func(context.Context, []string, stdio) int, args []string) map[string][]string {
	t.Helper()
	var made []*flag.FlagSet
	flagSetMade = func(fs *flag.FlagSet) { made = append(made, fs) }
	defer func() { flagSetMade = nil }()
	var out bytes.Buffer
	run(context.Background(), append(append([]string{}, args...), "-h"), stdio{in: strings.NewReader(""), out: &out, err: &out})
	got := map[string][]string{}
	for _, fs := range made {
		key := commandKey(fs.Name())
		got[key] = append(got[key], "") // the command exists even with no flag
		fs.VisitAll(func(f *flag.Flag) { got[key] = append(got[key], f.Name) })
	}
	return got
}

// extraProbes are the command lines, beside "<command> -h", that reach flag
// sets the command's summary does not name: init has one per setup mode, and
// plugin approve is missing from the plugin summary.
var extraProbes = map[string][][]string{
	"init":   {{"--remote"}, {"--setup-code", "x"}},
	"plugin": {{"approve"}},
}

// flagSetNames matches the literal names the source gives to flag sets.
var flagSetNames = regexp.MustCompile(`(?:\.flags|newFlagSet)\("([a-z]+(?: [a-z-]+)+)"`)

func actualCommandsAndFlags(t *testing.T, actual map[string]surfaceEntry) {
	t.Helper()
	// An agent marker in the environment must not change what -h reaches.
	for _, k := range agentMarkers {
		t.Setenv(k, "")
	}
	probed := map[string]bool{}
	probe := func(run func(context.Context, []string, stdio) int, args []string) {
		for key, flags := range probeFlags(t, run, args) {
			probed[key] = true
			for _, name := range flags {
				if name != "" {
					e := surfaceEntry{Kind: "flag", Name: key + " --" + name}
					actual[e.key()] = e
				}
			}
		}
	}
	for _, cmd := range commands() {
		if cmd.run == nil {
			continue // help is the table's own listing, not a command
		}
		actual["command "+cmd.name] = surfaceEntry{Kind: "command", Name: cmd.name}
		probe(cmd.run, nil)
		for _, extra := range extraProbes[cmd.name] {
			probe(cmd.run, extra)
		}
		for _, sub := range subcommandsOf(cmd.summary) {
			key := cmd.name + " " + sub
			probe(cmd.run, []string{sub})
			if !probed[key] {
				t.Errorf("the summary of %q lists %q, but running it makes no flag set", cmd.name, sub)
				continue
			}
			actual["command "+key] = surfaceEntry{Kind: "command", Name: key}
		}
	}

	// A subcommand the summary does not list is found by the name the
	// source gives its flag set.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range flagSetNames.FindAllStringSubmatch(string(raw), -1) {
			key := commandKey(m[1])
			if !probed[key] {
				t.Errorf("%s makes the flag set %q, which no probe reaches: list its subcommand in the command's summary or add it to extraProbes", file, m[1])
				continue
			}
			actual["command "+key] = surfaceEntry{Kind: "command", Name: key}
		}
	}
}

// envNames matches the quoted name of a BASALT_ or BASALTDB_ environment
// variable. Limit: only names written as one string in the Go source are
// seen; BASALTDB_REPO, which install.sh reads, is not listed.
var envNames = regexp.MustCompile(`"(BASALT(?:DB)?_[A-Z0-9_]+)"`)

func actualEnvironment(t *testing.T, actual map[string]surfaceEntry) {
	t.Helper()
	for _, root := range []string{"../../cmd", "../../internal", "../../pkg", "../../api"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testnotifier" { // a test helper's own variables
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range envNames.FindAllStringSubmatch(string(raw), -1) {
				if strings.Contains(m[1], "_TEST_") {
					continue // test helpers' own variables
				}
				e := surfaceEntry{Kind: "env", Name: m[1]}
				actual[e.key()] = e
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s for environment variables: %v", root, err)
		}
	}
}

func actualTools(t *testing.T, actual map[string]surfaceEntry) {
	t.Helper()
	tools, err := mcpcontract.Load()
	if err != nil {
		t.Fatalf("load the tool contracts: %v", err)
	}
	for _, tool := range tools {
		if tool.Status != mcpcontract.StatusImplemented {
			continue // contracted, not served
		}
		e := surfaceEntry{Kind: "mcp-tool", Name: tool.Name}
		actual[e.key()] = e
		props, _ := tool.InputSchema["properties"].(map[string]any)
		for arg := range props {
			e := surfaceEntry{Kind: "mcp-arg", Name: tool.Name + "." + arg}
			actual[e.key()] = e
		}
	}
}

// redirectSource matches a route line of web/_redirects.
var redirectSource = regexp.MustCompile(`^(/\S*)\s+/\S+\s+\d+\s*$`)

func actualPages(t *testing.T, actual map[string]surfaceEntry) {
	t.Helper()
	root := "../../web"
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "index.html" {
			return nil
		}
		dir, _ := filepath.Rel(root, filepath.Dir(path))
		p := "/"
		if dir != "." {
			p = "/" + filepath.ToSlash(dir) + "/"
		}
		e := surfaceEntry{Kind: "page", Name: p}
		actual[e.key()] = e
		return nil
	})
	if err != nil {
		t.Fatalf("walk web/: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "_redirects"))
	if err != nil {
		t.Fatalf("read web/_redirects: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := redirectSource.FindStringSubmatch(line); m != nil {
			e := surfaceEntry{Kind: "page", Name: m[1]}
			actual[e.key()] = e
		}
	}
}

func buildSurface(t *testing.T) map[string]surfaceEntry {
	t.Helper()
	actual := map[string]surfaceEntry{}
	actualCommandsAndFlags(t, actual)
	actualEnvironment(t, actual)
	actualTools(t, actual)
	actualPages(t, actual)
	return actual
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// surfaceDifferences lists what differs between the file's entries and the
// real surface, in both directions.
func surfaceDifferences(declared, actual map[string]surfaceEntry) []string {
	var diffs []string
	for _, k := range sortedKeys(actual) {
		if _, ok := declared[k]; !ok {
			diffs = append(diffs, k+" is in the binary or the page tree but not in contract/surface.json: "+
				"the surface has a budget, so a new entry needs a maintainer's sign-off")
		}
	}
	for _, k := range sortedKeys(declared) {
		if _, ok := actual[k]; !ok {
			diffs = append(diffs, k+" is in contract/surface.json but not in the binary or the page tree: delete the entry")
		}
	}
	return diffs
}

// epics are the epics that may remove an entry.
var epics = map[string]bool{
	"cli-cut": true, "direct-transport-removal": true, "one-setup-flow": true,
	"relay-carrier": true, "plugins-through-pages": true,
}

func declaredSurface(t *testing.T) map[string]surfaceEntry {
	t.Helper()
	file := loadSurface(t)
	if file.Version != 1 {
		t.Fatalf("surface.json version = %d, want 1", file.Version)
	}
	declared := map[string]surfaceEntry{}
	for _, e := range file.Entries {
		if e.Kind == "" || e.Name == "" {
			t.Errorf("entry %+v needs a kind and a name", e)
			continue
		}
		if _, dup := declared[e.key()]; dup {
			t.Errorf("%s is listed twice", e.key())
		}
		declared[e.key()] = e
		switch {
		case e.Status == "removing" && e.Epic == "":
			t.Errorf("%s is marked removing without the epic that removes it", e.key())
		case e.Epic != "" && !epics[e.Epic]:
			t.Errorf("%s names the unknown epic %q", e.key(), e.Epic)
		case e.Status != "" && e.Status != "removing":
			t.Errorf("%s has status %q, want \"removing\" or none", e.key(), e.Status)
		case e.Status == "" && e.Epic != "":
			t.Errorf("%s names the epic %q but is not marked removing", e.key(), e.Epic)
		}
	}
	return declared
}

func TestSurfaceBudget(t *testing.T) {
	declared := declaredSurface(t)
	for _, d := range surfaceDifferences(declared, buildSurface(t)) {
		t.Error(d)
	}
}

// TestSurfaceDifferences shows what the budget reports: a flag the file
// does not list, and an entry the binary no longer has.
func TestSurfaceDifferences(t *testing.T) {
	declared := map[string]surfaceEntry{
		"command init":      {Kind: "command", Name: "init"},
		"flag init --old":   {Kind: "flag", Name: "init --old"},
		"flag init --agent": {Kind: "flag", Name: "init --agent"},
	}
	actual := map[string]surfaceEntry{
		"command init":         {Kind: "command", Name: "init"},
		"flag init --agent":    {Kind: "flag", Name: "init --agent"},
		"flag init --brandnew": {Kind: "flag", Name: "init --brandnew"},
	}
	diffs := surfaceDifferences(declared, actual)
	if len(diffs) != 2 || !strings.HasPrefix(diffs[0], "flag init --brandnew is in the binary") ||
		!strings.HasPrefix(diffs[1], "flag init --old is in contract/surface.json") {
		t.Fatalf("differences = %q", diffs)
	}
	if got := surfaceDifferences(actual, actual); len(got) != 0 {
		t.Fatalf("equal surfaces differ: %q", got)
	}
}
