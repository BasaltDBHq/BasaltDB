package sdk

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// probeHook stands in for a hook the SDK learns later: an optional interface
// found by type assertion.
type probeHook interface {
	Probe(ctx context.Context, n int) (int, error)
}

type probePlugin struct{ fullPlugin }

func (*probePlugin) Probe(_ context.Context, n int) (int, error) { return n + 1, nil }

func withProbeHook(t *testing.T) {
	t.Helper()
	old := hookSpecs
	t.Cleanup(func() { hookSpecs = old })
	hookSpecs = append(hookSpecs[:len(hookSpecs):len(hookSpecs)], hookSpec{
		name: "probe.hook",
		declare: func(p Plugin) (HookDecl, bool) {
			_, ok := p.(probeHook)
			return HookDecl{Contract: "probe/1"}, ok
		},
		methods: map[string]func(Plugin) methodFunc{
			"probe": func(p Plugin) methodFunc {
				h := p.(probeHook)
				return func(ctx context.Context, params json.RawMessage) (any, *rpcError) {
					var in struct{ N int }
					if json.Unmarshal(params, &in) != nil {
						return nil, errBadParams
					}
					n, err := h.Probe(ctx, in.N)
					if err != nil {
						return nil, errInternal
					}
					return map[string]int{"n": n}, nil
				}
			},
		},
	})
}

// TestAHookAddedLaterLeavesOtherPluginsAlone: a plugin that implements the new
// hook's interface declares it and gets its methods; one written before the
// hook existed is unchanged and answers "method not found" for it.
func TestAHookAddedLaterLeavesOtherPluginsAlone(t *testing.T) {
	withProbeHook(t)
	req := `{"protocols":["basalt-plugin/1"],"hooks":["probe.hook"],"config":{},"limits":{"timeoutMs":1000}}`

	p := &probePlugin{fullPlugin: *newFull()}
	_, c := serveStdio(t, p)
	r := c.call("initialize", req)
	require.Nil(t, r.Error)
	require.Contains(t, string(r.Result), `"probe.hook":{"contract":"probe/1"}`)
	r = c.call("probe", `{"N":41}`)
	require.JSONEq(t, `{"n":42}`, string(r.Result))

	old := newFull() // implements no probe interface
	_, c = serveStdio(t, old)
	r = c.call("initialize", req)
	require.NotNil(t, r.Error, "it does not implement the hook the engine lists")
	r = c.call("initialize", initParams)
	require.Nil(t, r.Error)
	require.NotContains(t, string(r.Result), "probe.hook")
	require.Equal(t, codeNoMethod, c.call("probe", `{"N":1}`).Error.Code)
}

// TestWithHooksReplacesDiscovery: declaring hooks explicitly is exactly what
// the plugin says, even when it implements more.
func TestWithHooksReplacesDiscovery(t *testing.T) {
	withProbeHook(t)
	p := &probePlugin{fullPlugin: *newFull()}
	_, c := serveStdio(t, p, WithHooks(map[string]HookDecl{}))
	r := c.call("initialize", initParams)
	require.Nil(t, r.Error)
	require.JSONEq(t, `{}`, mustField(t, r.Result, "hooks"))
}

func mustField(t *testing.T, raw json.RawMessage, key string) string {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m))
	return string(m[key])
}

// TestImportsStayMovable: the SDK moves to its own repository, so non-test
// code may import the standard library, the plugin protocol types, the
// generated proto packages and public modules, and nothing else of the engine.
func TestImportsStayMovable(t *testing.T) {
	const module = "github.com/basaltdbhq/basaltdb/"
	allowed := map[string]bool{
		module + "internal/plugin/protocol":                          true,
		module + "api/plugin/proto/basalt/plugin/v1":                 true,
		module + "api/plugin/proto/basalt/plugin/v1/pluginv1connect": true,
	}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	found := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		require.NoError(t, err)
		for _, imp := range parsed.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(path, module) {
				found = true
				require.True(t, allowed[path], "%s imports %s", f, path)
			}
		}
	}
	require.True(t, found)

	// The template is an author's file: it imports the SDK and the standard library.
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join("template", "main.go"), nil, parser.ImportsOnly)
	require.NoError(t, err)
	for _, imp := range parsed.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if strings.Contains(path, ".") {
			require.Equal(t, module+"internal/plugin/sdk", path)
		}
	}
	_, err = os.Stat("template/main.go")
	require.NoError(t, err)
}

// TestSDKAndTemplateAreNotInTheReleaseBinary: the release binary is built from
// cmd/basalt, so neither the SDK nor the template may be among its packages.
func TestSDKAndTemplateAreNotInTheReleaseBinary(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/basaltdbhq/basaltdb/cmd/basalt").Output()
	require.NoError(t, err)
	require.Contains(t, string(out), "github.com/basaltdbhq/basaltdb/internal/plugin/protocol", "the list is the binary's packages")
	for _, pkg := range strings.Fields(string(out)) {
		require.NotContains(t, pkg, "internal/plugin/sdk", "the release binary links %s", pkg)
	}
}

// TestSDKReadsNoEnvironmentItself: the only environment access is the injected
// getenv, which Serve calls for SocketEnv alone.
func TestSDKReadsNoEnvironmentItself(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, call := range []string{"os.LookupEnv", "os.Environ", "os.ExpandEnv", "syscall.Getenv"} {
			require.NotContains(t, string(src), call, f)
		}
		if f != "options.go" { // os.Getenv appears once, as the default of getenv
			require.NotContains(t, string(src), "os.Getenv", f)
		}
	}
}
