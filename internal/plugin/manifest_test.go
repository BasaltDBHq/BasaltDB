package plugin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// contractTestdata holds the contract's valid and invalid manifest examples.
var contractTestdata = filepath.Join("..", "..", "api", "plugin", "testdata")

const detectorManifest = `{
  "manifestVersion": 1,
  "name": "acme-ner",
  "version": "1.4.0",
  "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": %HOOKS%,
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner" } },
  "files": { "bin/acme-ner": "sha256:d3e7eaa06a649502887713f958b9dda0dc22426fe4f73864221b888bb644465b" },
  "network": { "egress": [] }
}`

func withHooks(hooks string) []byte {
	return []byte(strings.Replace(detectorManifest, "%HOOKS%", hooks, 1))
}

func requireRefused(t *testing.T, err error, reason Refusal) *VerifyError {
	t.Helper()
	require.Error(t, err)
	var ve *VerifyError
	require.True(t, errors.As(err, &ve), "want a *VerifyError, got %T: %v", err, err)
	require.Equal(t, reason, ve.Reason, ve.Error())
	require.NotEmpty(t, ve.File)
	require.NotEmpty(t, ve.Why)
	return ve
}

// TestManifestHookRules: wire.verdict, wire.detect with feed.observe or
// approval.deliver, an entity type namespaced by another plugin's name and
// an unknown hook are refused with BAD_MANIFEST; feed.observe with
// approval.deliver is allowed.
func TestManifestHookRules(t *testing.T) {
	t.Parallel()
	const detect = `"wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] }`
	refused := map[string]string{
		"wire.verdict":             `{ "wire.verdict": { "contract": "verdict/1" } }`,
		"wire.verdict with detect": `{ ` + detect + `, "wire.verdict": { "contract": "verdict/1" } }`,
		"detect with observe":      `{ ` + detect + `, "feed.observe": { "contract": "feed/1" } }`,
		"detect with deliver":      `{ ` + detect + `, "approval.deliver": { "contract": "deliver/1" } }`,
		"foreign entity type":      `{ "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["other-plugin.EMPLOYEE_ID"] } }`,
		"foreign classify type":    `{ "classify.suggest": { "contract": "classify/1", "entityTypes": ["other-plugin.X"] } }`,
		"unknown hook":             `{ "wire.rewrite": { "contract": "rewrite/1" } }`,
		"no hooks":                 `{}`,
		"wrong contract":           `{ "feed.observe": { "contract": "detector/1" } }`,
		"observe with roles":       `{ "feed.observe": { "contract": "feed/1", "roles": ["VALUE"] } }`,
		"detect without types":     `{ "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": [] } }`,
		"null roles":               `{ "feed.observe": { "contract": "feed/1", "roles": null } }`,
	}
	for name, hooks := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseManifest(withHooks(hooks))
			ve := requireRefused(t, err, RefusedBadManifest)
			require.NotContains(t, ve.Error(), "other-plugin", "a refusal never quotes a value")
			require.NotContains(t, ve.Error(), "wire.rewrite", "a refusal never quotes a value")
		})
	}

	allowed := map[string]string{
		"observe with deliver": `{ "feed.observe": { "contract": "feed/1" }, "approval.deliver": { "contract": "deliver/1" } }`,
		"own entity type":      `{ "wire.detect": { "contract": "detector/1", "roles": ["VALUE", "NAME_CUE"], "entityTypes": ["acme-ner.EMPLOYEE_ID", "EMAIL"] } }`,
		"classify":             `{ "classify.suggest": { "contract": "classify/1", "entityTypes": ["acme-ner.X"] } }`,
		"unknown decl field":   `{ "feed.observe": { "contract": "feed/1", "later": true } }`,
	}
	for name, hooks := range allowed {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, err := ParseManifest(withHooks(hooks))
			require.NoError(t, err)
			require.Equal(t, "acme-ner", m.Name)
		})
	}
}

// TestManifestContractExamples: ParseManifest accepts every valid manifest
// example of the contract and refuses every invalid one, so the Go rules
// and the schema cannot drift apart unseen.
func TestManifestContractExamples(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join(contractTestdata, "*-manifest-*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(f)
			require.NoError(t, err)
			_, err = ParseManifest(b)
			if strings.HasPrefix(name, "valid-") {
				require.NoError(t, err)
				return
			}
			requireRefused(t, err, RefusedBadManifest)
		})
	}
	b, err := os.ReadFile(filepath.Join(contractTestdata, "signed", ManifestFile))
	require.NoError(t, err)
	_, err = ParseManifest(b)
	require.NoError(t, err, "the signed vector's manifest")
}

// TestManifestStrictJSON: JSON that encoding/json would accept loosely is
// refused: a repeated key, a key in another case, invalid UTF-8, trailing
// data and null for a required field.
func TestManifestStrictJSON(t *testing.T) {
	t.Parallel()
	base := string(withHooks(`{ "feed.observe": { "contract": "feed/1" } }`))
	cases := map[string]string{
		"repeated key":      strings.Replace(base, `"name": "acme-ner",`, `"name": "acme-ner", "name": "acme-ner",`, 1),
		"repeated hook key": strings.Replace(base, `"contract": "feed/1"`, `"contract": "feed/1", "contract": "feed/1"`, 1),
		"key in other case": strings.Replace(base, `"name":`, `"Name":`, 1),
		"invalid utf-8":     strings.Replace(base, `"Acme"`, "\"Ac\xffme\"", 1),
		"trailing data":     base + ` {}`,
		"null name":         strings.Replace(base, `"name": "acme-ner"`, `"name": null`, 1),
		"null egress":       strings.Replace(base, `"egress": []`, `"egress": null`, 1),
		"null arg":          strings.Replace(base, `"command": "bin/acme-ner"`, `"command": "bin/acme-ner", "args": [null]`, 1),
		"not an object":     `[]`,
		"too large":         base + strings.Repeat(" ", MaxManifestBytes),
		"version 2":         strings.Replace(base, `"manifestVersion": 1`, `"manifestVersion": 2`, 1),
		"entitlement":       strings.Replace(base, `"publisher": "Acme",`, `"publisher": "Acme", "entitlement": {},`, 1),
		"dot-dot path":      strings.Replace(base, `"files": {`, `"files": { "x/../y": "sha256:d3e7eaa06a649502887713f958b9dda0dc22426fe4f73864221b888bb644465b",`, 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseManifest([]byte(doc))
			requireRefused(t, err, RefusedBadManifest)
		})
	}
	m, err := ParseManifest([]byte(strings.Replace(base, `"publisher": "Acme",`, `"publisher": "Acme", "later": null,`, 1)))
	require.NoError(t, err, "an unknown top-level field is ignored, whatever its value")
	require.Equal(t, "Acme", m.Publisher)
	m, err = ParseManifest([]byte(strings.Replace(base, `"manifestVersion": 1`, `"manifestVersion": 1.0`, 1)))
	require.NoError(t, err, "1.0 is the integer 1, as in JSON Schema")
	require.Equal(t, 1, m.ManifestVersion)
}

// TestRemoteHostPort: the host:port network.egress must list for a URL.
func TestRemoteHostPort(t *testing.T) {
	t.Parallel()
	for u, want := range map[string]string{
		"https://ner.acme.example":          "ner.acme.example:443",
		"https://ner.acme.example:8443/x":   "ner.acme.example:8443",
		"https://[2001:db8::1]/v1":          "[2001:db8::1]:443",
		"https://192.0.2.1:9000":            "192.0.2.1:9000",
		"https://ner.acme.example/a b":      "ner.acme.example:443",
		"https://ner.acme.example/path/x.y": "ner.acme.example:443",
	} {
		got, ok := RemoteHostPort(u)
		require.True(t, ok, u)
		require.Equal(t, want, got, u)
	}
}
