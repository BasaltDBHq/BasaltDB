package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

const templatePackage = "github.com/basaltdbhq/basaltdb/internal/plugin/sdk/template"

// templateManifest is the manifest shipped in the template's comment, with the
// transport and the binary's hash filled in.
const templateManifest = `{
  "manifestVersion": 1, "name": "hello-feed", "version": "0.1.0", "publisher": "You",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "feed.observe": { "contract": "feed/1" } },
  "endpoint": { "local": { "transport": %q, "command": "bin/hello-feed", "args": %s } },
  "files": { "bin/hello-feed": "sha256:%x" },
  "network": { "egress": [] }
}
`

// buildTemplate compiles the SDK's template plugin, as an author would.
func buildTemplate(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "hello-feed")
	cmd := exec.Command("go", "build", "-o", out, templatePackage)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	b, err := cmd.CombinedOutput()
	require.NoError(t, err, string(b))
	return out
}

// TestTemplatePassesCheck follows the author's steps with the real commands:
// build the template from the SDK, write its manifest, generate a key, sign,
// trust the key, add, enable and check it, in same-user mode, over each
// transport. The plugin is the SDK's template, not a test double, so the
// initialize and health answers come from the SDK.
func TestTemplatePassesCheck(t *testing.T) {
	bin := buildTemplate(t)
	e := newPluginEngine(t)

	keys := filepath.Join(e.base, "authorkeys")
	r := e.runAuthor(nil, "keygen", "--out", keys)
	require.Equal(t, exitOK, r.code, r.stderr)
	var id, pub string
	_, err := fmt.Sscanf(r.stdout, "key id %s\npublic key %s\n", &id, &pub)
	require.NoError(t, err, r.stdout)
	priv := filepath.Join(keys, id+".key")
	e.person("trust", pub)

	for _, tc := range []struct {
		instance, transport string
		args                string
	}{
		{"stdio", "jsonrpc-stdio", `[]`},
		{"unix", "jsonrpc-unix", `[]`},
		{"grpc", "connectrpc", `["-transport", "connectrpc"]`},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			dir := filepath.Join(e.base, "hello-"+tc.instance)
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
			sum := copyExecutable(t, bin, filepath.Join(dir, "bin", "hello-feed"))
			manifest := fmt.Sprintf(templateManifest, tc.transport, tc.args, sum)
			require.NoError(t, os.WriteFile(filepath.Join(dir, plugin.ManifestFile), []byte(manifest), 0o644))

			r := e.runAuthor(nil, "sign", dir, "--key", priv)
			require.Equal(t, exitOK, r.code, r.stderr)
			e.person("add", dir, "--agents", "product_a", "--instance", tc.instance)
			e.person("enable", "hello-feed", "--instance", tc.instance)
			setEntryTimeout(t, e, tc.instance)

			r = e.run(nil, "", "check", "hello-feed", "--instance", tc.instance)
			require.Equal(t, exitOK, r.code, r.stderr)
			require.Regexp(t, `^plugin hello-feed/`+tc.instance+`: initialize [0-9.]+[µm]?s, health READY [0-9.]+[µm]?s\n$`, r.stdout)
		})
	}
}

// copyExecutable copies src to dst (mode 0755) and returns its SHA-256.
func copyExecutable(t *testing.T, src, dst string) [sha256.Size]byte {
	t.Helper()
	in, err := os.Open(src)
	require.NoError(t, err)
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	require.NoError(t, err)
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	require.NoError(t, err)
	require.NoError(t, out.Close())
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func setEntryTimeout(t *testing.T, e *pluginEngine, instance string) {
	t.Helper()
	require.NoError(t, config.UpdateConfig(e.configPath, config.Change{Apply: func(c *config.Config) error {
		c.Plugins[c.PluginIndex(plugin.EntryKey{Name: "hello-feed", Instance: instance})].TimeoutMs = config.MaxPluginTimeoutMs
		return nil
	}}))
}
