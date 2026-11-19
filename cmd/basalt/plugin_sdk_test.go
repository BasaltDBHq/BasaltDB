package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	plugincontract "github.com/basaltdbhq/basaltdb/api/plugin"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
	"github.com/basaltdbhq/basaltdb/internal/plugin/testnotifier"
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
			require.Regexp(t, `^plugin hello-feed/`+tc.instance+`: initialize [0-9.]+[µm]?s, health READY [0-9.]+[µm]?s\n`+
				`plugin hello-feed/`+tc.instance+`: feed\.observe lastSeq 2 [0-9.]+[µm]?s\n$`, r.stdout)
		})
	}
}

// TestCheckSendsEachNotifierHookItsSample: check sends the contract's sample
// to each declared notifier hook and prints one timing line per hook; a
// plugin that answers the feed sample wrongly fails check.
func TestCheckSendsEachNotifierHookItsSample(t *testing.T) {
	bin, err := testnotifier.Build(t.TempDir())
	require.NoError(t, err)
	e := newPluginEngine(t)
	keys := filepath.Join(e.base, "authorkeys")
	r := e.runAuthor(nil, "keygen", "--out", keys)
	require.Equal(t, exitOK, r.code, r.stderr)
	var id, pub string
	_, err = fmt.Sscanf(r.stdout, "key id %s\npublic key %s\n", &id, &pub)
	require.NoError(t, err, r.stdout)
	e.person("trust", pub)

	record := filepath.Join(t.TempDir(), "received.jsonl")
	for _, tc := range []struct {
		instance string
		mode     testnotifier.Mode
	}{{"good", testnotifier.ModeOK}, {"badseq", testnotifier.ModeBadSeq}} {
		dir := filepath.Join(e.base, "notifier-"+tc.instance)
		require.NoError(t, testnotifier.WriteDir(dir, bin, testnotifier.Options{Mode: tc.mode, Record: record}))
		r = e.runAuthor(nil, "sign", dir, "--key", filepath.Join(keys, id+".key"))
		require.Equal(t, exitOK, r.code, r.stderr)
		e.person("add", dir, "--agents", "product_a", "--instance", tc.instance)
		e.person("enable", testnotifier.Name, "--instance", tc.instance)
	}

	r = e.run(nil, "", "check", testnotifier.Name, "--instance", "good")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Regexp(t, `^plugin test-notifier/good: initialize [0-9.]+[µm]?s, health READY [0-9.]+[µm]?s\n`+
		`plugin test-notifier/good: approval\.deliver [0-9.]+[µm]?s\n`+
		`plugin test-notifier/good: feed\.observe lastSeq 2 [0-9.]+[µm]?s\n$`, r.stdout)

	got, err := testnotifier.ReadRecords(record)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "product_a", got[0].Agent)
	var notice struct {
		Time string `json:"time"`
		Data struct {
			ExpiresAt string `json:"expiresAt"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(got[0].Event, &notice))
	sent, err := time.Parse(time.RFC3339Nano, notice.Time)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), sent, time.Minute)
	expires, err := time.Parse(time.RFC3339Nano, notice.Data.ExpiresAt)
	require.NoError(t, err)
	require.Equal(t, time.Hour, expires.Sub(sent))
	require.Len(t, got[1].Events, 2)

	r = e.run(nil, "", "check", testnotifier.Name, "--instance", "badseq")
	require.NotEqual(t, exitOK, r.code)
	require.Contains(t, r.stderr, "feed.observe failed")
}

// TestCheckSamplesAreTheContractsBytes: only the agent, and the notice's time
// and expiry, differ from the contract's samples.
func TestCheckSamplesAreTheContractsBytes(t *testing.T) {
	feed, err := checkFeedParams("client_x")
	require.NoError(t, err)
	want := strings.ReplaceAll(string(plugincontract.CheckFeedSample()), `"product_a"`, `"client_x"`)
	var wantFeed protocol.FeedObserveRequest
	require.NoError(t, json.Unmarshal([]byte(want), &wantFeed))
	require.Equal(t, wantFeed, feed)
	require.Equal(t, "client_x", feed.Agent)
	require.NotContains(t, string(feed.Events), "product_a")

	now := time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC)
	notice, err := checkDeliverParams("client_x", now)
	require.NoError(t, err)
	want = strings.ReplaceAll(string(plugincontract.CheckDeliverSample()), `"product_a"`, `"client_x"`)
	want = strings.Replace(want, `"2026-01-01T00:00:01Z"`, `"2030-05-06T07:08:09Z"`, 1)
	want = strings.Replace(want, `"2026-01-02T00:00:01Z"`, `"2030-05-06T08:08:09Z"`, 1)
	var wantNotice protocol.ApprovalDeliverRequest
	require.NoError(t, json.Unmarshal([]byte(want), &wantNotice))
	require.Equal(t, wantNotice, notice)
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
