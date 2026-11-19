package plugincontract_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"
)

// ecmaUnicodeEscape is an ECMA-262 \uXXXX escape in a schema pattern.
var ecmaUnicodeEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

// longRepeat is a repeat count with an upper bound over 1000.
var longRepeat = regexp.MustCompile(`\{([0-9]+),[0-9]{4,}\}`)

// schemaBase is the base URL the schema files are loaded under, so a $ref
// between files (initialize's hooks point at the manifest's) resolves.
const schemaBase = "https://basaltvault.app/schemas/plugin/"

// maxConfigBytes is the bound on an entry's config, as compact JSON.
const maxConfigBytes = 16 * 1024

// kinds maps a fixture's kind (the part of its file name after valid- or
// invalid-) to the schema it is validated against and the contract rules
// the schema cannot express.
var kinds = []exampleKind{
	// Longest prefixes first: "initialize-request" before "initialize".
	{"initialize-request", "protocol/initialize.schema.json#/$defs/request", nil},
	{"initialize-response", "protocol/initialize.schema.json#/$defs/response", nil},
	{"health-request", "protocol/health.schema.json#/$defs/request", nil},
	{"health-response", "protocol/health.schema.json#/$defs/response", nil},
	{"shutdown-request", "protocol/shutdown.schema.json#/$defs/request", nil},
	{"shutdown-response", "protocol/shutdown.schema.json#/$defs/response", nil},
	{"manifest", "manifest.schema.json", []rule{ruleRemoteHostInEgress, ruleEntityTypePrefix, ruleCommandInFiles}},
	{"config", "config.schema.json", []rule{ruleUniqueEntries, ruleConfigSize, ruleConfigNoCredential}},
	{"event", "events.schema.json", nil},
	{"signature", "signature.schema.json", nil},
	{"person-request", "approval/person.schema.json#/$defs/request", nil},
	{"person-result-upload-begin", "approval/person.schema.json#/$defs/uploadBeginResult", nil},
	{"person-result-upload-part", "approval/person.schema.json#/$defs/uploadPartResult", nil},
	{"person-result-open", "approval/person.schema.json#/$defs/openResult", nil},
	{"person-result-list", "approval/person.schema.json#/$defs/listResult", nil},
	{"person-result-approve", "approval/person.schema.json#/$defs/approveResult", nil},
	{"person-result-disable", "approval/person.schema.json#/$defs/disableResult", nil},
	{"person-result-remove", "approval/person.schema.json#/$defs/removeResult", nil},
	{"person-error", "approval/person.schema.json#/$defs/error", nil},
	{"engine-entries", "engine-entries.schema.json", []rule{ruleUniqueEntries, ruleConfigSize, ruleConfigNoCredential}},
	{"wait-result", "approval/wait.schema.json", nil},
}

type exampleKind struct {
	prefix string
	schema string
	rules  []rule
}

// wantFailure says why each invalid example is invalid: "schema:<pointer>"
// is a schema keyword (a leaf error's schema location must end with it),
// "rule:<name>" a contract rule checked in Go. Every invalid example is
// listed, so none passes for the wrong reason.
var wantFailure = map[string]string{
	"invalid-manifest-unknown-hook.json":                     "schema:/properties/hooks/additionalProperties",
	"invalid-manifest-wire-verdict.json":                     "schema:/properties/hooks/properties/wire.verdict",
	"invalid-manifest-detect-with-observe.json":              "schema:/properties/hooks/allOf/0",
	"invalid-manifest-detect-with-deliver.json":              "schema:/properties/hooks/allOf/1",
	"invalid-manifest-remote-with-files.json":                "schema:/allOf/0/then",
	"invalid-manifest-remote-host-not-in-egress.json":        "rule:remoteHostInEgress",
	"invalid-manifest-remote-plain-http.json":                "schema:/$defs/remoteEndpoint/properties/url/pattern",
	"invalid-manifest-remote-url-with-password.json":         "schema:/$defs/remoteEndpoint/properties/url/pattern",
	"invalid-manifest-foreign-entity-type.json":              "rule:entityTypePrefix",
	"invalid-manifest-local-without-files.json":              "schema:/allOf/0/else/required",
	"invalid-manifest-command-not-in-files.json":             "rule:commandInFiles",
	"invalid-manifest-local-and-remote.json":                 "schema:/properties/endpoint/maxProperties",
	"invalid-manifest-entitlement.json":                      "schema:/properties/entitlement",
	"invalid-manifest-file-path-escapes.json":                "schema:/$defs/relativePath/pattern",
	"invalid-config-timeout-49.json":                         "schema:/$defs/entry/properties/timeoutMs/minimum",
	"invalid-config-timeout-60001.json":                      "schema:/$defs/entry/properties/timeoutMs/maximum",
	"invalid-config-no-agents.json":                          "schema:/$defs/entry/required",
	"invalid-config-over-16kib.json":                         "rule:configSize",
	"invalid-config-duplicate-instance.json":                 "rule:uniqueEntries",
	"invalid-config-secret-in-config.json":                   "rule:configNoCredential",
	"invalid-config-password-in-config.json":                 "rule:configNoCredential",
	"invalid-config-unknown-key.json":                        "schema:/$defs/entry/additionalProperties",
	"invalid-config-relative-credential-file.json":           "schema:/$defs/entry/properties/auth/properties/credentialFile/pattern",
	"invalid-config-bad-instance.json":                       "schema:/$defs/entry/properties/instance/pattern",
	"invalid-event-unknown-detail-key.json":                  "schema:/$defs/entryDetail/additionalProperties",
	"invalid-event-config-value.json":                        "schema:/$defs/entryDetail/additionalProperties",
	"invalid-event-remote-with-isolation.json":               "schema:/$defs/entryDetail/then",
	"invalid-event-local-without-isolation.json":             "schema:/$defs/entryDetail/else/required",
	"invalid-event-unknown-kind.json":                        "schema:/properties/kind/enum",
	"invalid-initialize-response-wire-verdict.json":          "schema:/properties/hooks/properties/wire.verdict",
	"invalid-health-response-unknown-status.json":            "schema:/$defs/response/properties/status/enum",
	"invalid-signature-alg.json":                             "schema:/properties/alg/const",
	"invalid-signature-der-sig.json":                         "schema:/properties/sig/pattern",
	"invalid-signature-bad-key-id.json":                      "schema:/properties/keyId/pattern",
	"invalid-event-bad-key-id.json":                          "schema:/$defs/keyId/pattern",
	"invalid-event-trust-removed-entry-detail.json":          "schema:/$defs/trustDetail/additionalProperties",
	"invalid-event-unknown-signer-with-key-id.json":          "schema:/$defs/entryDetail/allOf/0/then",
	"invalid-person-request-with-agent.json":                 "schema:/$defs/request/additionalProperties",
	"invalid-person-request-open-no-agents.json":             "schema:/$defs/openParams/required",
	"invalid-person-request-open-empty-agents.json":          "schema:/$defs/openParams/properties/agents/minItems",
	"invalid-person-request-open-auth.json":                  "schema:/$defs/settings/additionalProperties",
	"invalid-person-request-open-no-instance.json":           "schema:/$defs/openParams/required",
	"invalid-person-request-part-path-escapes.json":          "schema:/$defs/relativePath/pattern",
	"invalid-person-request-part-padded.json":                "schema:/$defs/partParams/properties/data/pattern",
	"invalid-person-request-list-with-params.json":           "schema:/$defs/noParams/additionalProperties",
	"invalid-person-request-unknown-method.json":             "schema:/$defs/request/properties/method/enum",
	"invalid-person-result-open-narrowed-with-approval.json": "schema:/$defs/openResult/then/properties/approvals/maxItems",
	"invalid-person-result-open-no-approvals.json":           "schema:/$defs/openResult/else/properties/approvals/minItems",
	"invalid-person-result-open-refused-with-id.json":        "schema:/$defs/openedApproval/oneOf/1",
	"invalid-person-result-list-engine-not-required.json":    "schema:/$defs/listedEntry/allOf/0/then/properties/approval/properties/required/const",
	"invalid-person-error-refused-without-reason.json":       "schema:/$defs/error/properties/error/then/required",
	"invalid-person-error-unknown-reason.json":               "schema:/$defs/error/properties/error/properties/reason/enum",
	"invalid-person-error-reason-without-refusal.json":       "schema:/$defs/error/properties/error/else",
	"invalid-engine-entries-no-approval.json":                "schema:/items/allOf/1/required",
	"invalid-wait-result-unknown-state.json":                 "schema:/properties/state/enum",
	"invalid-engine-entries-auth.json":                       "schema:/items/allOf/2",
	"invalid-engine-entries-duplicate-instance.json":         "rule:uniqueEntries",
	"invalid-engine-entries-secret-in-config.json":           "rule:configNoCredential",
}

// TestSchemaExamples: every testdata/valid-*.json passes its schema and the
// contract rules; every invalid-*.json fails for the reason wantFailure
// names.
func TestSchemaExamples(t *testing.T) {
	t.Parallel()
	compiler := newCompiler(t)
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	seen := map[string]bool{}
	for _, file := range files {
		base := filepath.Base(file)
		valid := strings.HasPrefix(base, "valid-")
		require.True(t, valid || strings.HasPrefix(base, "invalid-"), "%s: name it valid-* or invalid-*", base)
		kind := strings.TrimPrefix(strings.TrimPrefix(base, "valid-"), "invalid-")
		idx := slices.IndexFunc(kinds, func(k exampleKind) bool {
			return strings.HasPrefix(kind, k.prefix+"-") || kind == k.prefix+".json"
		})
		require.GreaterOrEqual(t, idx, 0, "%s: no schema for this example", base)
		k := kinds[idx]
		sch, err := compiler.Compile(schemaBase + k.schema)
		require.NoError(t, err, k.schema)

		raw, err := os.ReadFile(file)
		require.NoError(t, err)
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err, base)

		schemaErr := sch.Validate(inst)
		var ruleErrs []string
		for _, r := range k.rules {
			if err := r.check(raw); err != nil {
				ruleErrs = append(ruleErrs, "rule:"+r.name)
			}
		}
		if valid {
			require.NoError(t, schemaErr, base)
			require.Empty(t, ruleErrs, base)
			continue
		}
		seen[base] = true
		want, ok := wantFailure[base]
		require.True(t, ok, "%s: add the reason it is invalid to wantFailure", base)
		if strings.HasPrefix(want, "rule:") {
			require.NoError(t, schemaErr, "%s must pass the schema and fail only %s", base, want)
			require.Equal(t, []string{want}, ruleErrs, base)
			continue
		}
		require.Error(t, schemaErr, base)
		require.Empty(t, ruleErrs, "%s must fail only the schema", base)
		var ve *jsonschema.ValidationError
		require.True(t, errors.As(schemaErr, &ve))
		locs := leafLocations(ve)
		ptr := strings.TrimPrefix(want, "schema:")
		require.True(t, slices.ContainsFunc(locs, func(l string) bool { return strings.HasSuffix(l, ptr) }),
			"%s: want a failure at %s, got %v", base, ptr, locs)
	}
	for name := range wantFailure {
		require.True(t, seen[name], "wantFailure names %s, which is not in testdata", name)
	}
}

func newCompiler(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	// The MCP link schemas' patterns use ECMA-262 \uXXXX escapes, which Go's
	// regexp spells \x{XXXX}, and repeat counts over Go's limit of 1000,
	// which are read without their upper bound.
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		s = ecmaUnicodeEscape.ReplaceAllString(s, `\x{$1}`)
		return regexp.Compile(longRepeat.ReplaceAllString(s, `{$1,}`))
	})
	for _, f := range []string{
		"manifest.schema.json", "config.schema.json", "events.schema.json", "signature.schema.json",
		"protocol/initialize.schema.json", "protocol/health.schema.json", "protocol/shutdown.schema.json",
		"approval/binding.schema.json", "approval/request.schema.json", "approval/response.schema.json",
		"approval/result.schema.json", "approval/person.schema.json", "engine-entries.schema.json",
		"approval/wait.schema.json",
	} {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err, f)
		require.NoError(t, c.AddResource(schemaBase+f, doc), f)
		// The file's own $id is where the schema says it lives; the base
		// URL is where the test loads it. Both must name the same file.
		var head struct {
			ID string `json:"$id"`
		}
		require.NoError(t, json.Unmarshal(raw, &head))
		require.Equal(t, schemaBase+strings.Replace(f, ".schema.json", ".v1.json", 1), head.ID, f)
	}
	// The MCP schemas the plugin approval result shares, under their own ids.
	for _, f := range []string{"errors/next-step.schema.json", "links/link.schema.json", "links/request-file.schema.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "mcp", f))
		require.NoError(t, err)
		var head struct {
			ID string `json:"$id"`
		}
		require.NoError(t, json.Unmarshal(raw, &head))
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err, f)
		require.NoError(t, c.AddResource(head.ID, doc), f)
	}
	return c
}

// leafLocations returns the schema location of every leaf error, with its
// keyword: ".../manifest.schema.json#/properties/hooks/additionalProperties".
func leafLocations(ve *jsonschema.ValidationError) []string {
	if len(ve.Causes) == 0 {
		loc := ve.SchemaURL
		if kw := ve.ErrorKind.KeywordPath(); len(kw) > 0 {
			last := kw[len(kw)-1]
			if !strings.HasSuffix(loc, "/"+last) {
				loc += "/" + last
			}
		}
		// A failed "not" is reported at the schema that holds it, with or
		// without the keyword; compare without it.
		return []string{strings.TrimSuffix(loc, "/not")}
	}
	var out []string
	for _, c := range ve.Causes {
		out = append(out, leafLocations(c)...)
	}
	return out
}

// rule is a contract rule JSON Schema cannot express. The engine checks it
// at basalt plugin add and at start (CONTRACT.md, Plugins).
type rule struct {
	name  string
	check func(raw []byte) error
}

type testManifest struct {
	Name     string                     `json:"name"`
	Hooks    map[string]json.RawMessage `json:"hooks"`
	Endpoint struct {
		Local *struct {
			Command string `json:"command"`
		} `json:"local"`
		Remote *struct {
			URL string `json:"url"`
		} `json:"remote"`
	} `json:"endpoint"`
	Files   map[string]string `json:"files"`
	Network struct {
		Egress []string `json:"egress"`
	} `json:"network"`
}

type testEntry struct {
	Name     string          `json:"name"`
	Instance string          `json:"instance"`
	Config   json.RawMessage `json:"config"`
}

// defaultHTTPSPort is the port of an https URL that names none.
const defaultHTTPSPort = "443"

// ruleRemoteHostInEgress: a remote endpoint's host and port (443 when the
// URL names none) are exactly one network.egress entry.
var ruleRemoteHostInEgress = rule{"remoteHostInEgress", func(raw []byte) error {
	var m testManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Endpoint.Remote == nil {
		return nil
	}
	u, err := url.Parse(m.Endpoint.Remote.URL)
	if err != nil {
		return err
	}
	port := u.Port()
	if port == "" {
		port = defaultHTTPSPort
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if !slices.Contains(m.Network.Egress, host+":"+port) {
		return fmt.Errorf("%s:%s is not in network.egress", host, port)
	}
	return nil
}}

// ruleEntityTypePrefix: a namespaced entity type starts with the manifest's
// own name and a dot.
var ruleEntityTypePrefix = rule{"entityTypePrefix", func(raw []byte) error {
	var m testManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	for _, decl := range m.Hooks {
		var d struct {
			EntityTypes []string `json:"entityTypes"`
		}
		if err := json.Unmarshal(decl, &d); err != nil {
			return err
		}
		for _, et := range d.EntityTypes {
			if prefix, _, ok := strings.Cut(et, "."); ok && prefix != m.Name {
				return fmt.Errorf("entity type %s is not namespaced by %s", et, m.Name)
			}
		}
	}
	return nil
}}

// ruleCommandInFiles: a local endpoint's command is one of the files the
// manifest pins.
var ruleCommandInFiles = rule{"commandInFiles", func(raw []byte) error {
	var m testManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	// No files at all is the schema's refusal (a local plugin lists its
	// files), not this rule's.
	if m.Endpoint.Local == nil || m.Files == nil {
		return nil
	}
	if _, ok := m.Files[m.Endpoint.Local.Command]; !ok {
		return errors.New("command is not in files")
	}
	return nil
}}

// ruleUniqueEntries: (name, instance) is unique; no instance reads as
// "default".
var ruleUniqueEntries = rule{"uniqueEntries", func(raw []byte) error {
	var entries []testEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		inst := e.Instance
		if inst == "" {
			inst = "default"
		}
		key := e.Name + "/" + inst
		if seen[key] {
			return fmt.Errorf("duplicate entry %s", key)
		}
		seen[key] = true
	}
	return nil
}}

// ruleConfigSize: an entry's config is at most 16 KiB as compact JSON.
var ruleConfigSize = rule{"configSize", func(raw []byte) error {
	var entries []testEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}
	for _, e := range entries {
		var buf bytes.Buffer
		if len(e.Config) == 0 {
			continue
		}
		if err := json.Compact(&buf, e.Config); err != nil {
			return err
		}
		if buf.Len() > maxConfigBytes {
			return fmt.Errorf("config of %s is %d bytes", e.Name, buf.Len())
		}
	}
	return nil
}}

// ruleConfigNoCredential: no string in an entry's config, keys included, is
// a URL with a user name or password, or holds "password=" (the initArgs
// rule).
var ruleConfigNoCredential = rule{"configNoCredential", func(raw []byte) error {
	var entries []testEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}
	for _, e := range entries {
		if len(e.Config) == 0 {
			continue
		}
		var v any
		if err := json.Unmarshal(e.Config, &v); err != nil {
			return err
		}
		if s, ok := findCredential(v); ok {
			return fmt.Errorf("config of %s holds a credential (%d characters)", e.Name, len(s))
		}
	}
	return nil
}}

func findCredential(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		if strings.Contains(strings.ToLower(x), "password=") {
			return x, true
		}
		if u, err := url.Parse(x); err == nil && u.User != nil {
			return x, true
		}
	case map[string]any:
		for k, child := range x {
			if s, ok := findCredential(k); ok {
				return s, true
			}
			if s, ok := findCredential(child); ok {
				return s, true
			}
		}
	case []any:
		for _, child := range x {
			if s, ok := findCredential(child); ok {
				return s, true
			}
		}
	}
	return "", false
}

var (
	protoMessage = regexp.MustCompile(`(?m)^// (\S+\.schema\.json) (#/\S+)\nmessage (\w+) \{([^}]*)\}`)
	protoField   = regexp.MustCompile(`(?m)^\s*(?:repeated\s+|optional\s+)?(?:map<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*\d+;`)
	protoAnyMsg  = regexp.MustCompile(`(?m)^message (\w+) \{`)
)

// TestProtoMatchesSchemas: every message in plugin.proto names the JSON
// schema object it maps (a "// <file> #/<pointer>" line above it), and the
// two have the same fields: each JSON property has a snake_case proto field
// and the other way round. It reads the .proto as text.
func TestProtoMatchesSchemas(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("proto", "basalt", "plugin", "v1", "plugin.proto"))
	require.NoError(t, err)
	text := string(raw)

	all := protoAnyMsg.FindAllStringSubmatch(text, -1)
	matches := protoMessage.FindAllStringSubmatch(text, -1)
	require.Len(t, matches, len(all), "every message needs a // <schema file> #/<pointer> line right above it")

	for _, m := range matches {
		file, pointer, msg, body := m[1], m[2], m[3], m[4]
		var protoFields []string
		for _, f := range protoField.FindAllStringSubmatch(body, -1) {
			protoFields = append(protoFields, f[1])
		}
		schemaFields := schemaProperties(t, file, pointer)
		var want []string
		for _, p := range schemaFields {
			want = append(want, snake(p))
		}
		sort.Strings(protoFields)
		sort.Strings(want)
		require.Equal(t, want, protoFields, "message %s and %s %s differ", msg, file, pointer)
	}
}

// schemaProperties returns the property names of the object schema at
// pointer in file (a file under api/plugin/ or api/plugin/protocol/).
func schemaProperties(t *testing.T, file, pointer string) []string {
	t.Helper()
	path := filepath.Join("protocol", file)
	if _, err := os.Stat(path); err != nil {
		path = file
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var node any
	require.NoError(t, json.Unmarshal(raw, &node))
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "#/"), "/") {
		obj, ok := node.(map[string]any)
		require.True(t, ok, "%s %s", file, pointer)
		node, ok = obj[part]
		require.True(t, ok, "%s %s: no %s", file, pointer, part)
	}
	obj, ok := node.(map[string]any)
	require.True(t, ok)
	props, ok := obj["properties"].(map[string]any)
	require.True(t, ok, "%s %s has no properties", file, pointer)
	out := make([]string, 0, len(props))
	for name := range props {
		out = append(out, name)
	}
	return out
}

var upper = regexp.MustCompile(`[A-Z]`)

// snake maps a camelCase JSON name to its proto field name (entityTypes is
// entity_types), the inverse of proto3's JSON name mapping.
func snake(s string) string {
	return upper.ReplaceAllStringFunc(s, func(c string) string { return "_" + strings.ToLower(c) })
}

// manifestSigContext is the line a manifest signature's input starts with
// (CONTRACT.md, Plugins, Signing and the trust store).
const manifestSigContext = "basalt-plugin-manifest.1\n"

// sigLen is an ES256 signature as r ‖ s.
const sigLen = 64

// TestSignatureVectors: the signed manifest in testdata/signed verifies with
// crypto/ecdsa against its publisher key, its key id is derived from that
// key, and any 1-byte change to the manifest, or a signature of another
// length, fails. The vector's private key was discarded after signing.
func TestSignatureVectors(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("testdata", "signed")
	manifest, err := os.ReadFile(filepath.Join(dir, "basalt-plugin.json"))
	require.NoError(t, err)
	sigRaw, err := os.ReadFile(filepath.Join(dir, "basalt-plugin.json.sig"))
	require.NoError(t, err)
	pubPEM, err := os.ReadFile(filepath.Join(dir, "publisher.pub"))
	require.NoError(t, err)

	compiler := newCompiler(t)
	for file, raw := range map[string][]byte{"signature.schema.json": sigRaw, "manifest.schema.json": manifest} {
		sch, err := compiler.Compile(schemaBase + file)
		require.NoError(t, err)
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, sch.Validate(inst), file)
	}

	var sig struct {
		KeyID string `json:"keyId"`
		Alg   string `json:"alg"`
		Sig   string `json:"sig"`
	}
	require.NoError(t, json.Unmarshal(sigRaw, &sig))
	require.Equal(t, "ES256", sig.Alg)

	block, rest := pem.Decode(pubPEM)
	require.NotNil(t, block)
	require.Empty(t, bytes.TrimSpace(rest))
	require.Equal(t, "PUBLIC KEY", block.Type)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P256(), pub.Curve)

	sum := sha256.Sum256(block.Bytes)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:16]), sig.KeyID, "keyId is derived from the key")

	rawSig, err := base64.RawURLEncoding.Strict().DecodeString(sig.Sig)
	require.NoError(t, err)
	require.True(t, verifyManifest(pub, manifest, rawSig), "the vector verifies")

	// Each file the manifest pins has the hash it states.
	var m struct {
		Files map[string]string `json:"files"`
	}
	require.NoError(t, json.Unmarshal(manifest, &m))
	for path, want := range m.Files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		require.NoError(t, err)
		require.Equal(t, want, fmt.Sprintf("sha256:%x", sha256.Sum256(b)), path)
	}

	for i := range manifest {
		changed := slices.Clone(manifest)
		changed[i] ^= 0x01
		require.False(t, verifyManifest(pub, changed, rawSig), "a change at byte %d must fail", i)
	}
	require.False(t, verifyManifest(pub, append(slices.Clone(manifest), '\n'), rawSig), "an added byte must fail")
	require.False(t, verifyManifest(pub, manifest, rawSig[:sigLen-1]), "a short signature must fail")
	bare := sha256.Sum256(manifest)
	r := new(big.Int).SetBytes(rawSig[:sigLen/2])
	s := new(big.Int).SetBytes(rawSig[sigLen/2:])
	require.False(t, ecdsa.Verify(pub, bare[:], r, s), "the context line is part of the input")
}

// verifyManifest checks an ES256 signature, 64 bytes r ‖ s, over the
// context line and the manifest's exact bytes.
func verifyManifest(pub *ecdsa.PublicKey, manifest, sig []byte) bool {
	if len(sig) != sigLen {
		return false
	}
	digest := sha256.Sum256(append([]byte(manifestSigContext), manifest...))
	r := new(big.Int).SetBytes(sig[:sigLen/2])
	s := new(big.Int).SetBytes(sig[sigLen/2:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// The plugin approval page's fixed sentences (CONTRACT.md, Plugins, The
// plugin approval page). Placeholders are <name>-style; every template must
// appear in CONTRACT.md exactly as written here.
const (
	sentChangeOnAgain   = "You approved <name> before, and it was turned off. Turning it on again needs your approval."
	sentChange          = "This changes <name>, which you approved before."
	sentChangeVersion   = "Version <fromVersion> becomes <version>."
	sentChangeFiles     = "Its files change, but its version stays <version>."
	sentChangeSigner    = "Its publisher was <fromPublisher>; now it is <publisher>."
	sentChangeEndpoint  = "It moves from <fromWhere> to <where>."
	sentChangeIsolation = "How it is kept apart from Basalt changes."
	sentHooksAdded      = "It gets new access to: <hookLabels>."
	sentHooksRemoved    = "It no longer gets: <hookLabels>."
	sentNamesAdded      = "It now also looks for names in the text."
	sentValuesAdded     = "It now also looks for private values in the text."
	sentNamesRemoved    = "It no longer looks for names in the text."
	sentValuesRemoved   = "It no longer looks for private values in the text."
	sentEgressAdded     = "It now also connects to <hosts>."
	sentEgressRemoved   = "It no longer connects to <hosts>."
	sentAgentsAdded     = "It will now also be used for <agents>."
	sentAgentsRemoved   = "It will no longer be used for <agents>."
	sentSettingsChanged = "Its settings change."
	sentLevel1          = "Published by Basalt."
	sentLevel2          = "Nobody vouches for this plugin. Add it only if you trust where it came from."
	sentLevel3          = "Nobody vouches for this plugin. It runs a stranger's program on the computer Basalt runs on, with the same access as Basalt itself, so it could read your database password and the key Basalt uses to hide private values."
	sentTick            = "I know who made this plugin and I trust them with my data."
	sentRemote          = "It runs at <host>. Everything it sees is sent there."
	sentRemoteOnward    = "Basalt cannot check what runs there or where it sends things next."
	sentOwnUser         = "It runs on the computer Basalt runs on, as its own user, so it cannot read Basalt's files."
	sentSameAccess      = "It runs on the computer Basalt runs on, with the same access as Basalt itself."
	sentNoNetwork       = "It says it needs no network. That is not enforced on the computer Basalt runs on."
	sentEgressLimit     = "It says it connects only to <hosts>. That is not enforced on the computer Basalt runs on."
	sentNameCue         = "It also sees values from your database that appear in that text."
	sentUsedFor         = "Used for: <agents>."
	sentAskedBy         = "Asked by <agent>."
	sentFingerprint     = "Fingerprint: <fingerprint>"
	computerBasaltRuns  = "the computer Basalt runs on"
)

// hookSentence is what each hook sees, in plain words; hookLabel names that
// access in a change's list.
var (
	hookSentence = map[string]string{
		"wire.detect":      "It reads the text your agents send to the AI provider, before Basalt hides private values in it.",
		"feed.observe":     "It is told what your agents do in the database, such as which tables they change and how many rows, never the values.",
		"approval.deliver": "It delivers your approval links. Anyone who can read where it delivers them can see the rows of writes waiting for your approval.",
		"classify.suggest": "It reads the names and types of your tables and columns, never their values, and suggests which ones hold private data.",
	}
	hookLabel = map[string]string{
		"wire.detect":      "the text your agents send to the AI provider",
		"feed.observe":     "what your agents do in the database",
		"approval.deliver": "your approval links",
		"classify.suggest": "the names of your tables and columns",
	}
	addedRole   = map[string]string{"NAME_CUE": sentNamesAdded, "VALUE": sentValuesAdded}
	removedRole = map[string]string{"NAME_CUE": sentNamesRemoved, "VALUE": sentValuesRemoved}
	levelLine   = map[int]string{1: sentLevel1, 2: sentLevel2, 3: sentLevel3}
)

type approvalEndpoint struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
}

type approvalIsolation struct {
	Files   string `json:"files"`
	Network string `json:"network"`
}

type approvalChange struct {
	FromVersion        *string           `json:"fromVersion"`
	FromManifestSHA256 *string           `json:"fromManifestSha256"`
	FromSigner         *string           `json:"fromSigner"`
	FromEndpoint       *approvalEndpoint `json:"fromEndpoint"`
	FromIsolation      json.RawMessage   `json:"fromIsolation"`
	HooksAdded         []string          `json:"hooksAdded"`
	HooksRemoved       []string          `json:"hooksRemoved"`
	RolesAdded         []string          `json:"rolesAdded"`
	RolesRemoved       []string          `json:"rolesRemoved"`
	EgressAdded        []string          `json:"egressAdded"`
	EgressRemoved      []string          `json:"egressRemoved"`
	AgentsAdded        []string          `json:"agentsAdded"`
	AgentsRemoved      []string          `json:"agentsRemoved"`
	SettingsChanged    bool              `json:"settingsChanged"`
}

type approvalBinding struct {
	Kind           string                     `json:"kind"`
	ApprovalID     string                     `json:"approvalId"`
	RequestedBy    string                     `json:"requestedBy"`
	Agents         []string                   `json:"agents"`
	Name           string                     `json:"name"`
	Version        string                     `json:"version"`
	ManifestSHA256 string                     `json:"manifestSha256"`
	SettingsSHA256 string                     `json:"settingsSha256"`
	Hooks          []string                   `json:"hooks"`
	Roles          []string                   `json:"roles"`
	Egress         []string                   `json:"egress"`
	Endpoint       approvalEndpoint           `json:"endpoint"`
	Isolation      *approvalIsolation         `json:"isolation"`
	Signer         string                     `json:"signer"`
	Change         map[string]json.RawMessage `json:"change"`
}

// pageLevel derives the page's level from signer, endpoint and isolation.
func pageLevel(b approvalBinding) int {
	switch {
	case b.Signer == "KNOWN":
		return 1
	case b.Endpoint.Kind == "REMOTE", b.Isolation != nil && b.Isolation.Files == "OS_USER":
		return 2
	default:
		return 3
	}
}

// shortAgent is a role's name after "_agent_", as the pages show it.
func shortAgent(role string) string {
	if i := strings.Index(role, "_agent_"); i > 0 {
		return role[i+len("_agent_"):]
	}
	return role
}

func shortAgents(roles []string) string {
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = shortAgent(r)
	}
	return strings.Join(out, ", ")
}

func runsAt(e approvalEndpoint) string {
	if e.Kind == "LOCAL" {
		return computerBasaltRuns
	}
	return e.Host
}

func publisherOf(signer string) string {
	if signer == "KNOWN" {
		return "Basalt"
	}
	return "unknown"
}

func fill(template string, kv ...string) string {
	return strings.NewReplacer(kv...).Replace(template)
}

func hookLabels(hooks []string) string {
	out := make([]string, len(hooks))
	for i, h := range hooks {
		out[i] = hookLabel[h]
	}
	return strings.Join(out, "; ")
}

// changeSentences are the lines a change binding leads with, in the
// contract's order.
func changeSentences(t *testing.T, b approvalBinding) []string {
	t.Helper()
	if b.Change == nil {
		return nil
	}
	if len(b.Change) == 0 {
		return []string{fill(sentChangeOnAgain, "<name>", b.Name)}
	}
	var c approvalChange
	raw, err := json.Marshal(b.Change)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &c))
	out := []string{fill(sentChange, "<name>", b.Name)}
	switch {
	case c.FromVersion != nil:
		out = append(out, fill(sentChangeVersion, "<fromVersion>", *c.FromVersion, "<version>", b.Version))
	case c.FromManifestSHA256 != nil:
		out = append(out, fill(sentChangeFiles, "<version>", b.Version))
	}
	if c.FromSigner != nil {
		out = append(out, fill(sentChangeSigner, "<fromPublisher>", publisherOf(*c.FromSigner), "<publisher>", publisherOf(b.Signer)))
	}
	if c.FromEndpoint != nil {
		out = append(out, fill(sentChangeEndpoint, "<fromWhere>", runsAt(*c.FromEndpoint), "<where>", runsAt(b.Endpoint)))
	}
	if c.FromIsolation != nil {
		out = append(out, sentChangeIsolation)
	}
	if len(c.HooksAdded) > 0 {
		out = append(out, fill(sentHooksAdded, "<hookLabels>", hookLabels(c.HooksAdded)))
	}
	if len(c.HooksRemoved) > 0 {
		out = append(out, fill(sentHooksRemoved, "<hookLabels>", hookLabels(c.HooksRemoved)))
	}
	for _, r := range c.RolesAdded {
		out = append(out, addedRole[r])
	}
	for _, r := range c.RolesRemoved {
		out = append(out, removedRole[r])
	}
	if len(c.EgressAdded) > 0 {
		out = append(out, fill(sentEgressAdded, "<hosts>", strings.Join(c.EgressAdded, ", ")))
	}
	if len(c.EgressRemoved) > 0 {
		out = append(out, fill(sentEgressRemoved, "<hosts>", strings.Join(c.EgressRemoved, ", ")))
	}
	if len(c.AgentsAdded) > 0 {
		out = append(out, fill(sentAgentsAdded, "<agents>", shortAgents(c.AgentsAdded)))
	}
	if len(c.AgentsRemoved) > 0 {
		out = append(out, fill(sentAgentsRemoved, "<agents>", shortAgents(c.AgentsRemoved)))
	}
	if c.SettingsChanged {
		out = append(out, sentSettingsChanged)
	}
	return out
}

// pageSentences are the sentences the page shows for a binding, in the
// contract's order.
func pageSentences(t *testing.T, b approvalBinding) []string {
	t.Helper()
	out := changeSentences(t, b)
	level := pageLevel(b)
	out = append(out, levelLine[level])
	if level == 3 {
		out = append(out, sentTick)
	}
	switch {
	case b.Endpoint.Kind == "REMOTE":
		out = append(out, fill(sentRemote, "<host>", b.Endpoint.Host), sentRemoteOnward)
	case b.Isolation.Files == "OS_USER":
		out = append(out, sentOwnUser)
	case level == 1:
		out = append(out, sentSameAccess)
	}
	if b.Endpoint.Kind == "LOCAL" && b.Isolation.Network != "ENFORCED" {
		if len(b.Egress) == 0 {
			out = append(out, sentNoNetwork)
		} else {
			out = append(out, fill(sentEgressLimit, "<hosts>", strings.Join(b.Egress, ", ")))
		}
	}
	for _, h := range b.Hooks {
		out = append(out, hookSentence[h])
		if h == "wire.detect" && slices.Contains(b.Roles, "NAME_CUE") {
			out = append(out, sentNameCue)
		}
	}
	m := b.ManifestSHA256
	return append(out,
		fill(sentUsedFor, "<agents>", shortAgents(b.Agents)),
		fill(sentAskedBy, "<agent>", shortAgent(b.RequestedBy)),
		fill(sentFingerprint, "<fingerprint>", m[0:4]+" "+m[4:8]+" "+m[8:12]+" "+m[12:16]),
	)
}

// jsonbNode is a JSON value decoded with its object keys in text order.
type jsonbNode struct {
	kind   byte // '{', '[' or 's' (a scalar)
	obj    []jsonbMember
	arr    []jsonbNode
	scalar any // string, json.Number, bool or nil
}

type jsonbMember struct {
	key   string
	value jsonbNode
}

func decodeOrdered(dec *json.Decoder) (jsonbNode, error) {
	tok, err := dec.Token()
	if err != nil {
		return jsonbNode{}, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return jsonbNode{kind: 's', scalar: tok}, nil
	}
	n := jsonbNode{kind: byte(d)}
	for dec.More() {
		var key string
		if d == '{' {
			k, err := dec.Token()
			if err != nil {
				return n, err
			}
			key, _ = k.(string)
		}
		child, err := decodeOrdered(dec)
		if err != nil {
			return n, err
		}
		if d == '{' {
			n.obj = append(n.obj, jsonbMember{key, child})
		} else {
			n.arr = append(n.arr, child)
		}
	}
	_, err = dec.Token()
	return n, err
}

// writeJSONB writes n as Postgres writes jsonb text: object keys shorter
// first, then bytewise, never repeated; ", " and ": " as separators; strings
// quoted as escape_json quotes them. Numbers are written as given.
func writeJSONB(b *strings.Builder, n jsonbNode) error {
	switch n.kind {
	case '{':
		members := slices.Clone(n.obj)
		sort.SliceStable(members, func(i, j int) bool {
			a, c := members[i].key, members[j].key
			if len(a) != len(c) {
				return len(a) < len(c)
			}
			return a < c
		})
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				if members[i-1].key == m.key {
					return fmt.Errorf("repeated key %q", m.key)
				}
				b.WriteString(", ")
			}
			b.WriteString(escapeJSON(m.key))
			b.WriteString(": ")
			if err := writeJSONB(b, m.value); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case '[':
		b.WriteByte('[')
		for i, c := range n.arr {
			if i > 0 {
				b.WriteString(", ")
			}
			if err := writeJSONB(b, c); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		switch v := n.scalar.(type) {
		case string:
			b.WriteString(escapeJSON(v))
		case json.Number:
			b.WriteString(v.String())
		case bool:
			fmt.Fprint(b, v)
		default:
			b.WriteString("null")
		}
	}
	return nil
}

// escapeJSON quotes s as Postgres's escape_json does.
func escapeJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// requireJSONBText checks text is laid out exactly as Postgres writes jsonb.
func requireJSONBText(t *testing.T, text, what string) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	n, err := decodeOrdered(dec)
	require.NoError(t, err, what)
	require.False(t, dec.More(), what)
	var b strings.Builder
	require.NoError(t, writeJSONB(&b, n), what)
	require.Equal(t, text, b.String(), "%s is not in jsonb text layout", what)
}

type approvalVector struct {
	Name      string `json:"name"`
	Binding   string `json:"binding"`
	Challenge string `json:"challenge"`
	Settings  string `json:"settings"`
	Expect    struct {
		SettingsMatch *bool    `json:"settingsMatch"`
		Level         int      `json:"level"`
		Tick          bool     `json:"tick"`
		Sentences     []string `json:"sentences"`
		Error         string   `json:"error"`
	} `json:"expect"`
}

// TestPluginApprovalVectors checks api/plugin/approval/vectors.json against
// the contract: each binding and settings text is jsonb text, the binding,
// settings and request pass their schemas, the challenge is sha256 of the
// binding, and the settings check, level, tick and sentences follow the
// page's rules. The ledger details derived from each binding pass
// events.schema.json, and one that lists agents fails it. The response code
// decodes to response.schema.json and the result example passes
// result.schema.json. Every fixed sentence is written in CONTRACT.md.
func TestPluginApprovalVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("approval", "vectors.json"))
	require.NoError(t, err)
	var doc struct {
		Vectors       []approvalVector `json:"vectors"`
		Response      json.RawMessage  `json:"response"`
		ResultExample json.RawMessage  `json:"resultExample"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))

	compiler := newCompiler(t)
	compile := func(ref string) *jsonschema.Schema {
		s, err := compiler.Compile(schemaBase + ref)
		require.NoError(t, err, ref)
		return s
	}
	validate := func(s *jsonschema.Schema, text []byte) error {
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(text))
		require.NoError(t, err)
		return s.Validate(inst)
	}
	bindingSchema := compile("approval/binding.schema.json")
	settingsSchema := compile("approval/binding.schema.json#/$defs/settings")
	requestSchema := compile("approval/request.schema.json")
	eventSchema := compile("events.schema.json")

	levels := map[int]bool{}
	var changes, mismatches, wrongKinds int
	for _, v := range doc.Vectors {
		requireJSONBText(t, v.Binding, v.Name+" binding")
		requireJSONBText(t, v.Settings, v.Name+" settings")
		sum := sha256.Sum256([]byte(v.Binding))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), v.Challenge, v.Name)
		require.NoError(t, validate(settingsSchema, []byte(v.Settings)), v.Name)

		var b approvalBinding
		require.NoError(t, json.Unmarshal([]byte(v.Binding), &b), v.Name)
		if v.Expect.Error == "WRONG_KIND" {
			require.NotEqual(t, "PLUGIN", b.Kind, v.Name)
			require.Error(t, validate(bindingSchema, []byte(v.Binding)), v.Name)
			wrongKinds++
			continue
		}
		require.NoError(t, validate(bindingSchema, []byte(v.Binding)), v.Name)

		req, err := json.Marshal(map[string]string{"approvalId": b.ApprovalID, "binding": v.Binding, "settings": v.Settings})
		require.NoError(t, err)
		require.NoError(t, validate(requestSchema, req), v.Name)

		settingsSum := sha256.Sum256([]byte(v.Settings))
		match := fmt.Sprintf("%x", settingsSum) == b.SettingsSHA256
		require.NotNil(t, v.Expect.SettingsMatch, v.Name)
		require.Equal(t, *v.Expect.SettingsMatch, match, v.Name)
		if !match {
			require.Equal(t, "SETTINGS_MISMATCH", v.Expect.Error, v.Name)
			require.Zero(t, v.Expect.Level, "%s: a mismatch shows no level", v.Name)
			mismatches++
			continue
		}
		require.Empty(t, v.Expect.Error, v.Name)
		level := pageLevel(b)
		levels[level] = true
		require.Equal(t, v.Expect.Level, level, v.Name)
		require.Equal(t, level == 3, v.Expect.Tick, v.Name)
		require.Equal(t, pageSentences(t, b), v.Expect.Sentences, v.Name)
		if b.Change != nil {
			changes++
			// Version, hooks, roles, egress and endpoint are the manifest's,
			// so a change to any of them is a new manifest.
			for _, k := range []string{"fromVersion", "hooksAdded", "hooksRemoved", "rolesAdded", "rolesRemoved", "egressAdded", "egressRemoved", "fromEndpoint"} {
				if _, ok := b.Change[k]; ok {
					require.Contains(t, b.Change, "fromManifestSha256", "%s: %s changes the manifest", v.Name, k)
				}
			}
		}

		// The ledger details: the binding without the keys that name other
		// agents or describe only the request.
		var detail map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(v.Binding), &detail))
		for _, k := range []string{"kind", "database", "requestedBy", "agents", "change"} {
			delete(detail, k)
		}
		event := func(kind string) []byte {
			out, err := json.Marshal(map[string]any{"kind": kind, "detail": detail})
			require.NoError(t, err)
			return out
		}
		require.NoError(t, validate(eventSchema, event("PLUGIN_APPROVAL_PENDING")), v.Name)
		delete(detail, "expiresAt")
		detail["credentialId"] = json.RawMessage(`"q3Jv8sLk2mT0xYp1aBcD9w"`)
		detail["bindingSha256"] = json.RawMessage(fmt.Sprintf("%q", fmt.Sprintf("%x", sum)))
		require.NoError(t, validate(eventSchema, event("PLUGIN_APPROVED")), v.Name)
		detail["agents"] = json.RawMessage(`["basalt_agent_product_a"]`)
		require.Error(t, validate(eventSchema, event("PLUGIN_APPROVED")), "%s: no agent's ledger names another agent", v.Name)
	}
	require.Equal(t, map[int]bool{1: true, 2: true, 3: true}, levels, "one vector per page level")
	require.Positive(t, changes, "a change binding")
	require.Positive(t, mismatches, "a settings mismatch")
	require.Positive(t, wrongKinds, "a binding of another kind")

	// The response travels as basalt-plugin.1.<base64url(json)>: carry it
	// there and back, then check it.
	const codePrefix = "basalt-plugin.1."
	code := codePrefix + base64.RawURLEncoding.EncodeToString(doc.Response)
	body, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(code, codePrefix))
	require.NoError(t, err)
	require.JSONEq(t, string(doc.Response), string(body))
	responseSchema := compile("approval/response.schema.json")
	require.NoError(t, validate(responseSchema, body))
	var incomplete map[string]any
	require.NoError(t, json.Unmarshal(body, &incomplete))
	delete(incomplete, "signature")
	missing, err := json.Marshal(incomplete)
	require.NoError(t, err)
	require.Error(t, validate(responseSchema, missing), "a response without its signature")
	require.NoError(t, validate(compile("approval/result.schema.json"), doc.ResultExample))

	contract, err := os.ReadFile(filepath.Join("..", "..", "CONTRACT.md"))
	require.NoError(t, err)
	fixed := []string{
		sentChangeOnAgain, sentChange, sentChangeVersion, sentChangeFiles, sentChangeSigner, sentChangeEndpoint,
		sentChangeIsolation, sentHooksAdded, sentHooksRemoved, sentNamesAdded, sentValuesAdded, sentNamesRemoved,
		sentValuesRemoved, sentEgressAdded, sentEgressRemoved, sentAgentsAdded, sentAgentsRemoved, sentSettingsChanged,
		sentLevel1, sentLevel2, sentLevel3, sentTick, sentRemote, sentRemoteOnward, sentOwnUser, sentSameAccess,
		sentNoNetwork, sentEgressLimit, sentNameCue, sentUsedFor, sentAskedBy, sentFingerprint,
	}
	for _, m := range []map[string]string{hookSentence, hookLabel} {
		for _, s := range m {
			fixed = append(fixed, s)
		}
	}
	for _, s := range fixed {
		require.True(t, strings.Contains(string(contract), s), "CONTRACT.md must state the page's sentence exactly: %q", s)
	}
}
