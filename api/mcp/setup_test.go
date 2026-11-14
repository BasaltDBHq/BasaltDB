package mcpcontract_test

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// Setup code shape (CONTRACT.md, Setup from your laptop).
const (
	setupCodePrefix      = "basalt-setup."
	setupCodeFormat      = "1."
	setupCodeMaxLen      = 1500 // basalt init --remote refuses a longer code
	setupCheckBytes      = 4    // check: base64url of the first 4 bytes of sha256
	setupMaxInflated     = 64 << 10
	scramIterations      = 4096
	scramKeyLen          = sha256.Size
	fingerprintBytes     = 10              // setup fingerprint: 10 bytes, 20 hex digits
	fingerprintGroup     = 4               // hex digits per group
	maxRoleLen           = 63              // NAMEDATALEN - 1
	setupLifetime        = 24 * time.Hour  // CO-13
	setupClockSkew       = 5 * time.Minute // tolerated clock difference (RI-13)
	setupMinGuardVersion = 16              // the first guard with record_setup
	refusalNotSetupCode  = "NOT_A_SETUP_CODE"
	refusalUnsupported   = "UNSUPPORTED_FORMAT"
	refusalDamaged       = "DAMAGED"
	refusalInvalid       = "INVALID"
)

type setupFixtures struct {
	Description string `json:"description"`
	Verifiers   []struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
	} `json:"verifiers"`
	Valid []struct {
		Name        string         `json:"name"`
		Code        string         `json:"code"`
		Fingerprint string         `json:"fingerprint"`
		Payload     map[string]any `json:"payload"`
	} `json:"valid"`
	Invalid []struct {
		Name    string `json:"name"`
		Code    string `json:"code"`
		Refusal string `json:"refusal"`
	} `json:"invalid"`
	Laptop []laptopFixture `json:"laptop"`
}

// laptopFixture is what basalt init --setup-code decides for a code against
// a database state at a time (CONTRACT.md, basalt init --setup-code).
type laptopFixture struct {
	Name     string `json:"name"`
	Code     string `json:"code"`
	Now      string `json:"now"`
	Database struct {
		Prefix       string   `json:"prefix"`
		GuardVersion int      `json:"guardVersion"`
		Roles        []string `json:"roles"`
		Setups       []struct {
			SetupID   string `json:"setupId"`
			AgentRole string `json:"agentRole"`
			UsedAt    string `json:"usedAt"`
		} `json:"setups"`
	} `json:"database"`
	BinaryGuardVersion int      `json:"binaryGuardVersion"`
	Refusal            string   `json:"refusal"`
	Summary            []string `json:"summary"`
}

func loadSetupFixtures(t *testing.T) setupFixtures {
	t.Helper()
	raw, err := os.ReadFile("setup/setup-code.fixtures.json")
	require.NoError(t, err)
	var f setupFixtures
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&f))
	require.NotEmpty(t, f.Valid)
	require.NotEmpty(t, f.Invalid)
	require.NotEmpty(t, f.Verifiers)
	return f
}

func TestPortalSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "portal", []string{"portal-verify-result.schema.json"})
}

func TestSetupSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "setup", []string{"remote-init-result.schema.json", "setup-code.schema.json"})
}

// TestSetupCodeFixtures checks the golden setup codes against the codec
// rules of CONTRACT.md and setup-code.schema.json: every valid code decodes
// to its payload and validates, every invalid one is refused as stated.
func TestSetupCodeFixtures(t *testing.T) {
	t.Parallel()
	f := loadSetupFixtures(t)
	schema := readJSON(t, "setup/setup-code.schema.json")
	verifiers := map[string]bool{}
	for _, v := range f.Verifiers {
		verifiers[v.Verifier] = true
	}
	kinds := map[string]bool{}
	for _, v := range f.Valid {
		t.Run("valid/"+v.Name, func(t *testing.T) {
			t.Parallel()
			got, refusal := decodeSetupCode(t, schema, v.Code)
			require.Empty(t, refusal)
			require.Equal(t, v.Payload, got)
			require.LessOrEqual(t, len(stripSpace(v.Code)), setupCodeMaxLen)
			require.Equal(t, v.Fingerprint, setupFingerprint(t, got))
			if agent, ok := got["agent"].(map[string]any); ok {
				if verifier, ok := agent["verifier"].(string); ok {
					require.True(t, verifiers[verifier], "the payload's verifier is one of the verifier fixtures")
				}
			}
		})
		kind, ok := v.Payload["kind"].(string)
		require.True(t, ok, v.Name)
		kinds[kind] = true
	}
	require.Equal(t, map[string]bool{"INSTALL": true, "AGENT": true, "UPGRADE": true}, kinds, "a valid fixture per kind")
	for _, v := range f.Invalid {
		t.Run("invalid/"+v.Name, func(t *testing.T) {
			t.Parallel()
			_, refusal := decodeSetupCode(t, schema, v.Code)
			require.Equal(t, v.Refusal, refusal)
		})
	}
}

// decodeSetupCode follows CONTRACT.md, "The setup code", step by step, and
// returns the payload or the refusal.
func decodeSetupCode(t *testing.T, schema map[string]any, code string) (map[string]any, string) {
	t.Helper()
	code = stripSpace(code)
	rest, ok := strings.CutPrefix(code, setupCodePrefix)
	if !ok {
		return nil, refusalNotSetupCode
	}
	if !strings.HasPrefix(rest, setupCodeFormat) {
		return nil, refusalUnsupported
	}
	dot := strings.LastIndex(code, ".")
	body, check := code[:dot], code[dot+1:]
	sum := sha256.Sum256([]byte(body))
	if check != base64.RawURLEncoding.EncodeToString(sum[:setupCheckBytes]) {
		return nil, refusalDamaged
	}
	compressed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(body, setupCodePrefix+setupCodeFormat))
	if err != nil {
		return nil, refusalInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(compressed)), setupMaxInflated+1))
	if err != nil || len(raw) > setupMaxInflated {
		return nil, refusalInvalid
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, refusalInvalid
	}
	if format, ok := payload["format"].(float64); !ok || format != 1 {
		return nil, refusalUnsupported
	}
	if err := validateSchema(schema, schema, payload); err != nil {
		return nil, refusalInvalid
	}
	if err := checkSetupRules(payload); err != nil {
		return nil, refusalInvalid
	}
	return payload, ""
}

// checkSetupRules checks what the schema cannot state (CONTRACT.md, "Rules
// the schema cannot state"). The payload already passed the schema.
func checkSetupRules(p map[string]any) error {
	guard := p["guard"].(map[string]any)
	from, to := guard["from"].(float64), guard["to"].(float64)
	if from > to || (p["kind"] == "UPGRADE" && from == to) {
		return fmt.Errorf("guard from %v to %v", from, to)
	}
	expires, err := time.Parse(time.RFC3339, p["expiresAt"].(string))
	if err != nil {
		return err
	}
	if expires.After(uuidV7Time(p["setupId"].(string)).Add(setupLifetime)) {
		return fmt.Errorf("expiresAt more than %v after the setup id's time", setupLifetime)
	}
	agent, ok := p["agent"].(map[string]any)
	if !ok {
		return nil
	}
	if len(roleName(p)) > maxRoleLen {
		return fmt.Errorf("role %s longer than %d bytes", roleName(p), maxRoleLen)
	}
	write, read := agent["write"].([]any), agent["read"].([]any)
	if len(write)+len(read) == 0 {
		return fmt.Errorf("no tables")
	}
	for _, w := range write {
		if slices.Contains(read, w) {
			return fmt.Errorf("%v in both write and read", w)
		}
	}
	return nil
}

func roleName(p map[string]any) string {
	return p["prefix"].(string) + "_agent_" + p["agent"].(map[string]any)["name"].(string)
}

// uuidV7Time is the millisecond timestamp in the first 48 bits of a UUIDv7.
func uuidV7Time(id string) time.Time {
	ms, err := strconv.ParseInt(strings.ReplaceAll(id, "-", "")[:12], 16, 64)
	if err != nil {
		panic(err)
	}
	return time.UnixMilli(ms).UTC()
}

// setupKeyOrder is setup-code.schema.json's key order per object: the
// order the compact JSON of a code is written in.
var setupKeyOrder = map[string][]string{
	"":       {"format", "setupId", "kind", "prefix", "target", "guard", "build", "agent", "expiresAt"},
	"target": {"host", "port", "database", "supabaseRef"},
	"guard":  {"from", "to"},
	"agent":  {"name", "write", "read", "verifier", "statementTimeoutMs"},
}

// compactSetupJSON writes the decoded payload p back as compact JSON in
// the schema's key order, absent keys left out.
func compactSetupJSON(t *testing.T, object string, p map[string]any) string {
	t.Helper()
	parts := make([]string, 0, len(p))
	for _, k := range setupKeyOrder[object] {
		v, ok := p[k]
		if !ok {
			continue
		}
		var js string
		if inner, isObject := v.(map[string]any); isObject {
			js = compactSetupJSON(t, k, inner)
		} else {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			require.NoError(t, enc.Encode(v))
			js = strings.TrimSuffix(buf.String(), "\n")
		}
		parts = append(parts, fmt.Sprintf("%q:%s", k, js))
	}
	require.Len(t, parts, len(p), "every key of %q is in the schema's order", object)
	return "{" + strings.Join(parts, ",") + "}"
}

// setupFingerprint is the setup fingerprint (CONTRACT.md, The setup code):
// the first 10 bytes of sha256 over the payload's compact JSON in the
// schema's key order, in five groups of four hex digits.
func setupFingerprint(t *testing.T, p map[string]any) string {
	t.Helper()
	sum := sha256.Sum256([]byte("basalt-setup-fingerprint.2\n" + compactSetupJSON(t, "", p)))
	h := hex.EncodeToString(sum[:fingerprintBytes])
	groups := make([]string, 0, len(h)/fingerprintGroup)
	for i := 0; i < len(h); i += fingerprintGroup {
		groups = append(groups, h[i:i+fingerprintGroup])
	}
	return strings.Join(groups, " ")
}

// TestSetupLaptopFixtures runs the checks of basalt init --setup-code, in
// CONTRACT.md's order, over the laptop fixtures: the refusal, or the summary
// lines the person must see (the agent and role named, a password
// replacement said out loud, the fingerprint, prefix and timeout).
func TestSetupLaptopFixtures(t *testing.T) {
	t.Parallel()
	f := loadSetupFixtures(t)
	require.NotEmpty(t, f.Laptop)
	schema := readJSON(t, "setup/setup-code.schema.json")
	refusals := map[string]bool{}
	for _, l := range f.Laptop {
		refusals[l.Refusal] = true
		t.Run(l.Name, func(t *testing.T) {
			t.Parallel()
			p, refusal := decodeSetupCode(t, schema, l.Code)
			require.Empty(t, refusal)
			now, err := time.Parse(time.RFC3339, l.Now)
			require.NoError(t, err)
			got, summary := laptopDecision(t, p, l, now)
			require.Equal(t, l.Refusal, got)
			for _, line := range l.Summary {
				require.Contains(t, summary, line)
			}
		})
	}
	for _, r := range []string{"", "EXPIRED", "SETUP_ID_IN_FUTURE", "BINARY_TOO_OLD", "PREFIX_MISMATCH", "USED", "SUPERSEDED", "ROLE_EXISTS", "ROLE_MISSING"} {
		require.True(t, refusals[r], "a laptop fixture for %q", r)
	}
}

func laptopDecision(t *testing.T, p map[string]any, l laptopFixture, now time.Time) (string, string) {
	expires, _ := time.Parse(time.RFC3339, p["expiresAt"].(string))
	id, kind, prefix := p["setupId"].(string), p["kind"].(string), p["prefix"].(string)
	to := int(p["guard"].(map[string]any)["to"].(float64))
	db := l.Database
	switch {
	case !now.Before(expires):
		return "EXPIRED", ""
	case uuidV7Time(id).After(now.Add(setupClockSkew)):
		return "SETUP_ID_IN_FUTURE", ""
	case expires.After(now.Add(setupLifetime + setupClockSkew)):
		return "EXPIRY_TOO_FAR", ""
	case to > l.BinaryGuardVersion:
		return "BINARY_TOO_OLD", ""
	case to < setupMinGuardVersion:
		return "GUARD_TOO_OLD", ""
	case db.Prefix != "" && db.Prefix != prefix:
		return "PREFIX_MISMATCH", ""
	}
	role := ""
	if kind != "UPGRADE" {
		role = roleName(p)
	}
	for _, s := range db.Setups {
		switch {
		case s.SetupID == id:
			return "USED", ""
		case role != "" && s.AgentRole == role && s.SetupID > id:
			return "SUPERSEDED", ""
		}
	}
	exists := slices.Contains(db.Roles, role)
	switch {
	case kind == "INSTALL" && exists:
		return "ROLE_EXISTS", ""
	case kind == "AGENT" && !exists:
		return "ROLE_MISSING", ""
	}
	return "", laptopSummary(t, p, role)
}

func laptopSummary(t *testing.T, p map[string]any, role string) string {
	kind, prefix := p["kind"].(string), p["prefix"].(string)
	guard := p["guard"].(map[string]any)
	who := "your agent"
	var lines []string
	agent, _ := p["agent"].(map[string]any)
	if agent != nil {
		who = agent["name"].(string)
	}
	_, rotates := agent["verifier"]
	switch {
	case kind == "UPGRADE":
		lines = append(lines, fmt.Sprintf("This upgrades Basalt's guard from version %v to %v; no agent changes.", guard["from"], guard["to"]),
			fmt.Sprintf("Prefix %s.", prefix))
	case kind == "INSTALL":
		lines = append(lines, fmt.Sprintf("This creates the agent %s (role %s). Its password comes from the code: only whoever made this code can log in as %s.", who, role, role))
	case rotates:
		lines = append(lines, fmt.Sprintf("This replaces the password of the existing agent %s (role %s): only whoever made this code can then log in as %s. Run it only if %s itself gave you this code.", who, role, role, who))
	default:
		lines = append(lines, fmt.Sprintf("This changes the tables of the existing agent %s (role %s); its password stays.", who, role))
	}
	if agent != nil {
		lines = append(lines, fmt.Sprintf("Prefix %s, statement timeout %v ms, at most 8 connections.", prefix, agent["statementTimeoutMs"]))
	}
	lines = append(lines, fmt.Sprintf("Setup fingerprint: %s. Check that %s shows the same fingerprint.", setupFingerprint(t, p), who))
	return strings.Join(lines, "\n")
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// TestSCRAMVerifierFixtures recomputes each verifier fixture (RFC 5802 and
// RFC 7677, as Postgres stores it) so the codec's verifier is pinned.
func TestSCRAMVerifierFixtures(t *testing.T) {
	t.Parallel()
	schema := readJSON(t, "setup/setup-code.schema.json")
	verifierSchema := mustMap(t, mustMap(t, schema["$defs"])["verifier"])
	for _, v := range loadSetupFixtures(t).Verifiers {
		salt, err := base64.StdEncoding.DecodeString(v.Salt)
		require.NoError(t, err)
		salted, err := pbkdf2.Key(sha256.New, v.Password, salt, scramIterations, scramKeyLen)
		require.NoError(t, err)
		clientKey := hmacSHA256(salted, "Client Key")
		storedKey := sha256.Sum256(clientKey)
		serverKey := hmacSHA256(salted, "Server Key")
		b64 := base64.StdEncoding.EncodeToString
		want := fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", scramIterations, b64(salt), b64(storedKey[:]), b64(serverKey))
		require.Equal(t, want, v.Verifier, v.Name)
		require.NoError(t, validateSchema(schema, verifierSchema, v.Verifier), v.Name)
	}
}

func hmacSHA256(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// TestAgentOperatedSteps checks the catalog's agent-operated rules
// (CONTRACT.md, Next steps): AGENT RUN_COMMAND appears only in variants,
// OPERATOR only in the entries both modes share, and every variant replaces
// an existing entry and is listed in CONTRACT.md.
func TestAgentOperatedSteps(t *testing.T) {
	t.Parallel()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)

	shared := map[string][]mcpcontract.StepKind{}
	for _, e := range c.Errors {
		shared[mcpcontract.VariantError+":"+e.Code+"/"+e.Reason+"/"+e.Tool] = e.Steps
	}
	for _, w := range c.Warnings {
		shared[mcpcontract.VariantWarning+":"+w.Code+"//"] = w.Steps
	}
	for _, p := range c.Problems {
		shared[mcpcontract.VariantProblem+":"+p.Code+"//"] = p.Steps
	}
	for _, r := range c.Results {
		shared["RESULT:"+r.Tool+"/"+r.Case] = r.Steps
	}
	for key, steps := range shared {
		for _, s := range steps {
			agentCommand := s.Actor == mcpcontract.ActorAgent && s.Action == mcpcontract.ActionRunCommand
			require.False(t, agentCommand, "%s: AGENT RUN_COMMAND only in agentOperated variants", key)
		}
	}

	variants := map[string]bool{}
	for _, v := range c.AgentOperated {
		key := v.Kind + ":" + v.Code + "/" + v.Reason + "/" + v.Tool
		require.False(t, variants[key], "duplicate variant %s", key)
		variants[key] = true
		_, ok := shared[key]
		require.True(t, ok, "%s: a variant replaces an existing entry", key)
		requireSteps(t, key, v.Steps)
		for _, s := range v.Steps {
			require.NotEqual(t, mcpcontract.ActorOperator, s.Actor, "%s: a variant names AGENT or PERSON", key)
		}
		got, ok := c.AgentOperatedEntry(v.Kind, v.Code, v.Reason, v.Tool)
		require.True(t, ok, key)
		require.Equal(t, v, got)
	}
	require.Equal(t, variants, contractAgentOperated(t), "CONTRACT.md agent-operated table and next-steps.json differ")
}

func TestResolveOperatorSteps(t *testing.T) {
	t.Parallel()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	e, ok := c.ErrorEntry("UNAVAILABLE", "SETUP_EXPIRED", "write")
	require.True(t, ok)
	require.Equal(t, mcpcontract.ActorOperator, e.Steps[0].Actor)

	for operatedBy, actor := range map[string]string{
		mcpcontract.OperatedByAgent:  mcpcontract.ActorAgent,
		mcpcontract.OperatedByPerson: mcpcontract.ActorPerson,
		"":                           mcpcontract.ActorPerson, // config unreadable: the safe default
	} {
		got := mcpcontract.Resolve(e.Steps, operatedBy)
		require.Equal(t, actor, got[0].Actor, operatedBy)
		require.Equal(t, mcpcontract.ActionRunCommand, got[0].Action)
		require.Equal(t, e.Steps[1:], got[1:], "only OPERATOR steps change")
	}
	require.Equal(t, mcpcontract.ActorOperator, e.Steps[0].Actor, "Resolve does not change the catalog")
}

var agentOperatedRow = regexp.MustCompile("^\\| (error|warning|problem) \\| `([A-Z][A-Z0-9_]*)` \\| (?:`([A-Z][A-Z0-9_]*)`|—) \\|")

func contractAgentOperated(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../CONTRACT.md")
	require.NoError(t, err)
	rows := map[string]bool{}
	inSection := false
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "#") {
			inSection = line == "### Next steps on an agent-operated engine"
			continue
		}
		if m := agentOperatedRow.FindStringSubmatch(line); inSection && m != nil {
			rows[strings.ToUpper(m[1])+":"+m[2]+"/"+m[3]+"/"] = true
		}
	}
	require.NotEmpty(t, rows, "no agent-operated variants found in CONTRACT.md")
	return rows
}

func TestStatusReportsSetup(t *testing.T) {
	t.Parallel()
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), "status")
	require.True(t, ok)
	required, ok := tool.OutputSchema["required"].([]any)
	require.True(t, ok)
	require.Contains(t, required, "enforcement")
	require.Contains(t, required, "setup")
	props := mustMap(t, tool.OutputSchema["properties"])
	require.Equal(t, map[string]bool{"ENGINE_AND_GUARD": true, "GUARD_ONLY": true}, schemaEnum(t, tool.OutputSchema, "enforcement"))
	require.Equal(t, map[string]bool{"NONE": true, "PENDING": true, "EXPIRED": true, "DONE": true},
		schemaEnum(t, mustMap(t, props["setup"]), "state"))
}

// validateSchema checks value against node, a JSON Schema subset: the
// keywords setup-code.schema.json uses. root resolves "#/$defs/..." refs.
func validateSchema(root, node map[string]any, value any) error {
	if ref, ok := node["$ref"].(string); ok {
		def, ok := mapAt(root, strings.TrimPrefix(ref, "#/"))
		if !ok {
			return fmt.Errorf("unresolved $ref %s", ref)
		}
		return validateSchema(root, def, value)
	}
	if err := validateCombinators(root, node, value); err != nil {
		return err
	}
	if err := validateType(node, value); err != nil {
		return err
	}
	switch v := value.(type) {
	case map[string]any:
		return validateObject(root, node, v)
	case []any:
		return validateArray(root, node, v)
	case string:
		return validateString(node, v)
	case float64:
		return validateNumber(node, v)
	}
	return nil
}

func mapAt(root map[string]any, path string) (map[string]any, bool) {
	cur := root
	for part := range strings.SplitSeq(path, "/") {
		next, ok := cur[part].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func validateCombinators(root, node map[string]any, value any) error {
	if alts, ok := node["oneOf"].([]any); ok {
		matched := 0
		for _, alt := range alts {
			if validateSchema(root, alt.(map[string]any), value) == nil {
				matched++
			}
		}
		if matched != 1 {
			return fmt.Errorf("oneOf: %d alternatives match", matched)
		}
	}
	if not, ok := node["not"].(map[string]any); ok && validateSchema(root, not, value) == nil {
		return fmt.Errorf("matches not")
	}
	if c, ok := node["const"]; ok && fmt.Sprint(c) != fmt.Sprint(value) {
		return fmt.Errorf("%v is not %v", value, c)
	}
	if enum, ok := node["enum"].([]any); ok {
		for _, e := range enum {
			if e == value {
				return nil
			}
		}
		return fmt.Errorf("%v not in enum", value)
	}
	return nil
}

func validateType(node map[string]any, value any) error {
	typ, ok := node["type"].(string)
	if !ok {
		return nil
	}
	var match bool
	switch v := value.(type) {
	case map[string]any:
		match = typ == "object"
	case []any:
		match = typ == "array"
	case string:
		match = typ == "string"
	case bool:
		match = typ == "boolean"
	case float64:
		match = typ == "number" || (typ == "integer" && v == math.Trunc(v))
	}
	if !match {
		return fmt.Errorf("%v is not %s", value, typ)
	}
	return nil
}

func validateObject(root, node, v map[string]any) error {
	props, _ := node["properties"].(map[string]any)
	required, _ := node["required"].([]any)
	for _, r := range required {
		if _, ok := v[r.(string)]; !ok {
			return fmt.Errorf("missing %s", r)
		}
	}
	for k, val := range v {
		prop, ok := props[k].(map[string]any)
		if !ok {
			if node["additionalProperties"] == false {
				return fmt.Errorf("unknown key %s", k)
			}
			continue
		}
		if err := validateSchema(root, prop, val); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

func validateArray(root, node map[string]any, v []any) error {
	if n, ok := node["maxItems"].(float64); ok && float64(len(v)) > n {
		return fmt.Errorf("more than %v items", n)
	}
	if n, ok := node["minItems"].(float64); ok && float64(len(v)) < n {
		return fmt.Errorf("fewer than %v items", n)
	}
	seen := map[string]bool{}
	for _, item := range v {
		key := fmt.Sprint(item)
		if node["uniqueItems"] == true && seen[key] {
			return fmt.Errorf("duplicate item %v", item)
		}
		seen[key] = true
		if items, ok := node["items"].(map[string]any); ok {
			if err := validateSchema(root, items, item); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateString(node map[string]any, v string) error {
	if p, ok := node["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(v) {
		return fmt.Errorf("%q does not match %s", v, p)
	}
	if n, ok := node["maxLength"].(float64); ok && float64(len([]rune(v))) > n {
		return fmt.Errorf("%q longer than %v", v, n)
	}
	if n, ok := node["minLength"].(float64); ok && float64(len([]rune(v))) < n {
		return fmt.Errorf("%q shorter than %v", v, n)
	}
	if node["format"] == "date-time" {
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			return fmt.Errorf("%q is not a date-time", v)
		}
	}
	return nil
}

func validateNumber(node map[string]any, v float64) error {
	if n, ok := node["minimum"].(float64); ok && v < n {
		return fmt.Errorf("%s below %v", strconv.FormatFloat(v, 'f', -1, 64), n)
	}
	if n, ok := node["maximum"].(float64); ok && v > n {
		return fmt.Errorf("%s above %v", strconv.FormatFloat(v, 'f', -1, 64), n)
	}
	return nil
}
