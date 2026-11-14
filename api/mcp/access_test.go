package mcpcontract_test

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Passkey confirmation (CONTRACT.md, Access and audit, People and passkeys).
const (
	confirmBindingPrefix = "basalt-passkey-confirm.1\n"
	fingerprintDomain    = "basalt-passkey-fp.1\n"
	fingerprintLen       = 10 // bytes of sha256 the fingerprint shows: 80 bits
	crockfordAlphabet    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var crockford = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)

type confirmVectors struct {
	Description string `json:"description"`
	Cases       []struct {
		Name      string         `json:"name"`
		X         string         `json:"x"`
		Y         string         `json:"y"`
		Fields    map[string]any `json:"fields"`
		Binding   string         `json:"binding"`
		Challenge string         `json:"challenge"`
	} `json:"cases"`
	InvalidPersonNames []struct {
		Name       string `json:"name"`
		PersonName string `json:"personName"`
	} `json:"invalidPersonNames"`
}

// TestAccessSchemas checks the Access and audit schemas follow the wire rules.
func TestAccessSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "access", []string{
		"access-list.schema.json",
		"confirm-binding.schema.json",
		"confirm-request.schema.json",
		"confirm-response.schema.json",
		"ledger-detail.schema.json",
		"level-policies.schema.json",
		"register-agent-request.schema.json",
		"register-agent-result.schema.json",
	})
}

// TestConfirmVectors recomputes every confirmation vector from its fields: the
// fingerprint from the key, the binding as Postgres prints the jsonb, and the
// challenge from the binding. A second, independent implementation made the
// file, so both must agree byte for byte.
func TestConfirmVectors(t *testing.T) {
	t.Parallel()
	v := loadConfirmVectors(t)
	schema := readJSON(t, filepath.Join("access", "confirm-binding.schema.json"))
	kinds := map[string]bool{}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			f := c.Fields
			want := passkeyFingerprint(t, f["credentialId"].(string), c.X, c.Y)
			require.Equal(t, want, f["fingerprint"], "fingerprint")

			require.True(t, strings.HasPrefix(c.Binding, confirmBindingPrefix))
			require.Equal(t, confirmBindingPrefix+jsonbText(t, f), c.Binding, "binding")

			var parsed map[string]any
			require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(c.Binding, confirmBindingPrefix)), &parsed))
			require.Equal(t, f, parsed, "the binding parses back to its fields")
			require.NoError(t, validateSchema(schema, schema, parsed))

			sum := sha256.Sum256([]byte(c.Binding))
			require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), c.Challenge, "challenge")
			if f["level"] == "ADMIN" {
				require.Nil(t, f["roleOid"])
				require.Nil(t, f["roleName"])
			} else {
				require.NotNil(t, f["roleOid"])
				require.NotNil(t, f["roleName"])
			}
		})
		kinds[c.Fields["kind"].(string)] = true
	}
	require.Equal(t, map[string]bool{"CONFIRM": true, "REJECT": true}, kinds, "vectors cover both kinds")
}

// TestConfirmBindingNeverJSON checks the prefix keeps a confirmation from
// verifying as an approval or revert signature, whose challenges hash a JSON
// binding, or as a widen or reveal proof.
func TestConfirmBindingNeverJSON(t *testing.T) {
	t.Parallel()
	for _, c := range loadConfirmVectors(t).Cases {
		require.False(t, json.Valid([]byte(c.Binding)), c.Name)
		require.False(t, strings.HasPrefix(c.Binding, "basalt-rescope.1"), c.Name)
		require.False(t, strings.HasPrefix(c.Binding, "basalt-reveal.1"), c.Name)
	}
	contract := readContract(t)
	for _, prefix := range []string{`basalt-passkey-confirm.1\n`, `basalt-passkey-fp.1\n`, "basalt-confirm.1."} {
		require.Contains(t, contract, prefix)
	}
}

// TestInvalidPersonNames checks the names register_passkey refuses also fail
// the schema's personName rule.
func TestInvalidPersonNames(t *testing.T) {
	t.Parallel()
	v := loadConfirmVectors(t)
	schema := readJSON(t, filepath.Join("access", "confirm-binding.schema.json"))
	rule := mustMap(t, mustMap(t, schema["properties"])["personName"])
	require.NotEmpty(t, v.InvalidPersonNames)
	for _, n := range v.InvalidPersonNames {
		require.Error(t, validateSchema(schema, rule, n.PersonName), n.Name)
	}
	for _, c := range v.Cases {
		require.NoError(t, validateSchema(schema, rule, c.Fields["personName"]), c.Name)
	}
}

// auditChainRow matches a row of the ledger table in CONTRACT.md, Access and
// audit, The audit chain: | `ROLE_ENROLLED` | ... or two kinds in one row.
var auditChainRow = regexp.MustCompile("(?m)^\\| `([A-Z_]+)`(?:, `([A-Z_]+)`)? \\|")

// TestAccessLedgerKinds checks the ledger detail schema and the audit chain
// table in CONTRACT.md list the same kinds.
func TestAccessLedgerKinds(t *testing.T) {
	t.Parallel()
	schema := readJSON(t, filepath.Join("access", "ledger-detail.schema.json"))
	defs := mustMap(t, schema["$defs"])
	inSchema := map[string]bool{}
	for kind, def := range mustMap(t, schema["x-kinds"]) {
		require.Regexp(t, screamingCase, kind)
		_, ok := defs[def.(string)]
		require.True(t, ok, "%s names a missing $defs entry", kind)
		inSchema[kind] = true
	}
	section := contractSection(t, "### The audit chain")
	inContract := map[string]bool{}
	for _, m := range auditChainRow.FindAllStringSubmatch(section, -1) {
		for _, k := range m[1:] {
			if k != "" {
				inContract[k] = true
			}
		}
	}
	require.Equal(t, inSchema, inContract)
}

// TestAccessRefusalDetails checks every BS012 detail the contract lists is
// SCREAMING_SNAKE_CASE and that the two an agent can meet are reasons of
// PERMISSION_DENIED in the next-steps catalog.
func TestAccessRefusalDetails(t *testing.T) {
	t.Parallel()
	section := contractSection(t, "### Guard objects")
	i := strings.Index(section, "`BS012` `ACCESS_REFUSED` details:")
	require.GreaterOrEqual(t, i, 0)
	line, _, _ := strings.Cut(section[i:], "\n")
	details := regexp.MustCompile("`([A-Z_0-9]+)`").FindAllStringSubmatch(line, -1)
	require.Greater(t, len(details), 10)
	names := make([]string, 0, len(details)-2)
	for _, d := range details[2:] {
		names = append(names, d[1])
	}
	for _, want := range []string{"PG_VERSION", "LEVEL_UNENROLLED", "LEVEL_PRIVILEGE", "PRIVILEGE_NOT_HELD", "AGENT_CALLER"} {
		require.Contains(t, names, want)
	}
	raw, err := os.ReadFile(filepath.Join("errors", "next-steps.json"))
	require.NoError(t, err)
	var catalog struct {
		Errors []struct {
			Code, Reason string
		} `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(raw, &catalog))
	var reasons []string
	for _, e := range catalog.Errors {
		if e.Code == "PERMISSION_DENIED" {
			reasons = append(reasons, e.Reason)
		}
	}
	require.Subset(t, reasons, []string{"LEVEL_UNENROLLED", "LEVEL_PRIVILEGE"})
}

func loadConfirmVectors(t *testing.T) confirmVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("access", "confirm-vectors.json"))
	require.NoError(t, err)
	var v confirmVectors
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	require.NoError(t, dec.Decode(&v))
	require.NotEmpty(t, v.Description)
	require.NotEmpty(t, v.Cases)
	for _, c := range v.Cases {
		for k, val := range c.Fields {
			if n, ok := val.(json.Number); ok {
				f, err := n.Float64()
				require.NoError(t, err)
				c.Fields[k] = f
			}
		}
	}
	return v
}

func passkeyFingerprint(t *testing.T, credentialID, x, y string) string {
	t.Helper()
	h := sha256.New()
	h.Write([]byte(fingerprintDomain))
	for _, s := range []string{credentialID, x, y} {
		b, err := base64.RawURLEncoding.DecodeString(s)
		require.NoError(t, err)
		h.Write(b)
	}
	s := crockford.EncodeToString(h.Sum(nil)[:fingerprintLen])
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// jsonbText prints a flat object as Postgres prints a jsonb value: keys
// shorter first, then bytewise; ", " and ": " between items; strings escaped
// as escape_json does.
func jsonbText(t *testing.T, fields map[string]any) string {
	t.Helper()
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(a, b)
	})
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		var v string
		switch val := fields[k].(type) {
		case nil:
			v = "null"
		case string:
			v = escapeJSONPostgres(val)
		case float64:
			v = strconv.FormatFloat(val, 'f', -1, 64)
		default:
			t.Fatalf("field %s: unexpected %T", k, val)
		}
		parts = append(parts, escapeJSONPostgres(k)+": "+v)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func escapeJSONPostgres(s string) string {
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

func readContract(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "CONTRACT.md"))
	require.NoError(t, err)
	return string(raw)
}

// contractSection returns CONTRACT.md from the heading up to the next heading
// of the same or a higher level.
func contractSection(t *testing.T, heading string) string {
	t.Helper()
	contract := readContract(t)
	i := strings.Index(contract, "\n"+heading+"\n")
	require.GreaterOrEqual(t, i, 0, heading)
	rest := contract[i+1+len(heading):]
	level := strings.Repeat("#", strings.Index(heading, " "))
	for j := 0; j < len(rest); {
		k := strings.Index(rest[j:], "\n#")
		if k < 0 {
			break
		}
		start := j + k + 1
		hashes := len(rest[start:]) - len(strings.TrimLeft(rest[start:], "#"))
		if hashes <= len(level) {
			return rest[:start]
		}
		j = start
	}
	return rest
}

// TestLevelPolicyMarks pins the rule that keeps a copy from showing an agent
// more rows than its role: every review mark exists in the plan schema, a
// marked restrictive copy is written as USING (false), and a marked
// permissive copy is left out unless the admin replaces it.
func TestLevelPolicyMarks(t *testing.T) {
	t.Parallel()
	schema := readJSON(t, filepath.Join("access", "level-policies.schema.json"))
	copyItem := mustMap(t, mustMap(t, mustMap(t, mustMap(t, mustMap(t, mustMap(t, mustMap(t,
		schema["properties"])["tables"])["items"])["properties"])["policies"])["items"])["properties"])
	marks := mustMap(t, mustMap(t, copyItem["reviewNeeded"])["items"])["enum"]
	require.ElementsMatch(t, []any{"IDENTITY", "SUBQUERY", "FUNCTION"}, marks)
	_, ok := copyItem["replacement"]
	require.True(t, ok, "a marked copy can take the admin's replacement")

	section := contractSection(t, "### Agent groups and mirrored policies (AA-17)")
	for _, want := range []string{
		"a marked **restrictive** source policy gets a restrictive copy `USING (false)`",
		"a marked **permissive** source policy is left out",
		"gets a restrictive copy `USING (false)` for the group, permissive or restrictive alike",
		"an **allow list**, not a deny list",
		"an unmarked restrictive copy can never be left out",
		"`session_user` is a member of `<prefix>_lvl_<p_role>`",
	} {
		require.Contains(t, section, want)
	}
}
