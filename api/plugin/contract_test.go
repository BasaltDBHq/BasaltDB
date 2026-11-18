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
	"invalid-manifest-unknown-hook.json":              "schema:/properties/hooks/additionalProperties",
	"invalid-manifest-wire-verdict.json":              "schema:/properties/hooks/properties/wire.verdict",
	"invalid-manifest-detect-with-observe.json":       "schema:/properties/hooks/allOf/0",
	"invalid-manifest-detect-with-deliver.json":       "schema:/properties/hooks/allOf/1",
	"invalid-manifest-remote-with-files.json":         "schema:/allOf/0/then",
	"invalid-manifest-remote-host-not-in-egress.json": "rule:remoteHostInEgress",
	"invalid-manifest-remote-plain-http.json":         "schema:/$defs/remoteEndpoint/properties/url/pattern",
	"invalid-manifest-remote-url-with-password.json":  "schema:/$defs/remoteEndpoint/properties/url/pattern",
	"invalid-manifest-foreign-entity-type.json":       "rule:entityTypePrefix",
	"invalid-manifest-local-without-files.json":       "schema:/allOf/0/else/required",
	"invalid-manifest-command-not-in-files.json":      "rule:commandInFiles",
	"invalid-manifest-local-and-remote.json":          "schema:/properties/endpoint/maxProperties",
	"invalid-manifest-entitlement.json":               "schema:/properties/entitlement",
	"invalid-manifest-file-path-escapes.json":         "schema:/$defs/relativePath/pattern",
	"invalid-config-timeout-49.json":                  "schema:/$defs/entry/properties/timeoutMs/minimum",
	"invalid-config-timeout-60001.json":               "schema:/$defs/entry/properties/timeoutMs/maximum",
	"invalid-config-no-agents.json":                   "schema:/$defs/entry/required",
	"invalid-config-over-16kib.json":                  "rule:configSize",
	"invalid-config-duplicate-instance.json":          "rule:uniqueEntries",
	"invalid-config-secret-in-config.json":            "rule:configNoCredential",
	"invalid-config-password-in-config.json":          "rule:configNoCredential",
	"invalid-config-unknown-key.json":                 "schema:/$defs/entry/additionalProperties",
	"invalid-config-relative-credential-file.json":    "schema:/$defs/entry/properties/auth/properties/credentialFile/pattern",
	"invalid-config-bad-instance.json":                "schema:/$defs/entry/properties/instance/pattern",
	"invalid-event-unknown-detail-key.json":           "schema:/$defs/entryDetail/additionalProperties",
	"invalid-event-config-value.json":                 "schema:/$defs/entryDetail/additionalProperties",
	"invalid-event-remote-with-isolation.json":        "schema:/$defs/entryDetail/then",
	"invalid-event-local-without-isolation.json":      "schema:/$defs/entryDetail/else/required",
	"invalid-event-unknown-kind.json":                 "schema:/properties/kind/enum",
	"invalid-initialize-response-wire-verdict.json":   "schema:/properties/hooks/properties/wire.verdict",
	"invalid-health-response-unknown-status.json":     "schema:/$defs/response/properties/status/enum",
	"invalid-signature-alg.json":                      "schema:/properties/alg/const",
	"invalid-signature-der-sig.json":                  "schema:/properties/sig/pattern",
	"invalid-signature-bad-key-id.json":               "schema:/properties/keyId/pattern",
	"invalid-event-bad-key-id.json":                   "schema:/$defs/keyId/pattern",
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
	for _, f := range []string{
		"manifest.schema.json", "config.schema.json", "events.schema.json", "signature.schema.json",
		"protocol/initialize.schema.json", "protocol/health.schema.json", "protocol/shutdown.schema.json",
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

	rawSig, err := base64.RawURLEncoding.DecodeString(sig.Sig)
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
	require.False(t, verifyManifest(pub, manifest[len(manifestSigContext):], rawSig), "the context line is part of the input")
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
