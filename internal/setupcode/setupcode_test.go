package setupcode_test

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

const fixturesFile = "../../api/mcp/setup/setup-code.fixtures.json"

type fixtures struct {
	Verifiers []struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
	} `json:"verifiers"`
	Valid []struct {
		Name        string          `json:"name"`
		Code        string          `json:"code"`
		Fingerprint string          `json:"fingerprint"`
		Payload     json.RawMessage `json:"payload"`
	} `json:"valid"`
	Invalid []struct {
		Name    string `json:"name"`
		Code    string `json:"code"`
		Refusal string `json:"refusal"`
	} `json:"invalid"`
	Laptop []laptopFixture `json:"laptop"`
}

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

func loadFixtures(t testing.TB) fixtures {
	t.Helper()
	raw, err := os.ReadFile(fixturesFile)
	require.NoError(t, err)
	var f fixtures
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Valid)
	require.NotEmpty(t, f.Invalid)
	require.NotEmpty(t, f.Laptop)
	require.NotEmpty(t, f.Verifiers)
	return f
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func refusalOf(t *testing.T, err error) setupcode.Refusal {
	t.Helper()
	var e *setupcode.Error
	require.True(t, errors.As(err, &e), "error %v is a *setupcode.Error", err)
	return e.Refusal
}

func TestValidFixtures(t *testing.T) {
	t.Parallel()
	for _, v := range loadFixtures(t).Valid {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			var want setupcode.Payload
			require.NoError(t, json.Unmarshal(v.Payload, &want))

			got, err := setupcode.Decode(v.Code)
			require.NoError(t, err)
			require.Equal(t, want, got)
			require.Equal(t, v.Fingerprint, got.Fingerprint())

			code, err := setupcode.Encode(got)
			require.NoError(t, err)
			require.Equal(t, stripSpace(v.Code), code, "round-trips byte for byte")
			require.LessOrEqual(t, len(code), setupcode.MaxCodeLen)
		})
	}
}

func TestInvalidFixtures(t *testing.T) {
	t.Parallel()
	for _, v := range loadFixtures(t).Invalid {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			_, err := setupcode.Decode(v.Code)
			require.Error(t, err)
			require.Equal(t, setupcode.Refusal(v.Refusal), refusalOf(t, err))
		})
	}
}

func TestLaptopFixtures(t *testing.T) {
	t.Parallel()
	for _, l := range loadFixtures(t).Laptop {
		t.Run(l.Name, func(t *testing.T) {
			t.Parallel()
			p, err := setupcode.Decode(l.Code)
			require.NoError(t, err)
			now, err := time.Parse(time.RFC3339, l.Now)
			require.NoError(t, err)

			err = laptopCheck(t, p, l, now)
			if l.Refusal == "" {
				require.NoError(t, err)
				shown := strings.Join(setupcode.Summary(p, setupcode.SummaryState{GuardVersion: l.Database.GuardVersion}), "\n")
				for _, line := range l.Summary {
					require.Contains(t, shown, line)
				}
				return
			}
			require.Error(t, err)
			require.Equal(t, setupcode.Refusal(l.Refusal), refusalOf(t, err))
		})
	}
}

func laptopCheck(t *testing.T, p setupcode.Payload, l laptopFixture, now time.Time) error {
	t.Helper()
	if err := setupcode.CheckNotConnectOnly(p); err != nil {
		return err
	}
	if err := setupcode.CheckLocal(p, now, l.BinaryGuardVersion); err != nil {
		return err
	}
	db := setupcode.Database{Prefix: l.Database.Prefix, Roles: l.Database.Roles}
	for _, s := range l.Database.Setups {
		usedAt, err := time.Parse(time.RFC3339, s.UsedAt)
		require.NoError(t, err)
		db.Setups = append(db.Setups, setupcode.RecordedSetup{SetupID: s.SetupID, AgentRole: s.AgentRole, UsedAt: usedAt})
	}
	return setupcode.CheckDatabase(p, db)
}

func validPayload(t testing.TB) setupcode.Payload {
	t.Helper()
	p, err := setupcode.Decode(loadFixtures(t).Valid[0].Code)
	require.NoError(t, err)
	return p
}

// rawCode builds a code around any JSON, with a correct check, so the
// decoder's payload rules can be exercised past the check digits.
func rawCode(t *testing.T, payload []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write(payload)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return withCheck("basalt-setup.1." + base64.RawURLEncoding.EncodeToString(buf.Bytes()))
}

func withCheck(body string) string {
	sum := sha256.Sum256([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(sum[:4])
}

func TestDecodeMessages(t *testing.T) {
	t.Parallel()
	_, err := setupcode.Decode("hello")
	require.EqualError(t, err, "This is not a Basalt setup code.")
	_, err = setupcode.Decode("basalt-setup.1.abc.AAAAAA")
	require.EqualError(t, err, "This setup code is damaged; copy it again.")
	_, err = setupcode.Decode("basalt-setup.2.abc.AAAAAA")
	require.EqualError(t, err, "This setup code is newer than basalt on this computer: update it from the release page.")
	// Layout version 1 cut short is not a newer layout.
	for _, code := range []string{"basalt-setup.1", "basalt-setup.1\n"} {
		_, err = setupcode.Decode(code)
		require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err), "%q", code)
	}
	_, err = setupcode.Decode("basalt-setup.12")
	require.Equal(t, setupcode.RefusalUnsupportedFormat, refusalOf(t, err))
}

func TestDecodeRefusesPayloads(t *testing.T) {
	t.Parallel()
	good, err := json.Marshal(validPayload(t))
	require.NoError(t, err)
	replace := func(old, repl string) []byte {
		require.Contains(t, string(good), old)
		return []byte(strings.Replace(string(good), old, repl, 1))
	}
	cases := map[string]struct {
		payload []byte
		refusal setupcode.Refusal
	}{
		"not json":                  {[]byte("{"), setupcode.RefusalInvalid},
		"json array":                {[]byte("[1]"), setupcode.RefusalInvalid},
		"no format":                 {replace(`"format":1,`, ""), setupcode.RefusalUnsupportedFormat},
		"format as a string":        {replace(`"format":1`, `"format":"1"`), setupcode.RefusalUnsupportedFormat},
		"format 2 with unknown key": {replace(`"format":1`, `"format":2,"engine":{}`), setupcode.RefusalUnsupportedFormat},
		"key in another case":       {replace(`"setupId"`, `"SetupId"`), setupcode.RefusalInvalid},
		"null write list":           {replace(`"write":["public.leads"]`, `"write":null`), setupcode.RefusalInvalid},
		"null supabase ref":         {replace(`"supabaseRef":"abcdefghijklmnopqrst"`, `"supabaseRef":null`), setupcode.RefusalInvalid},
		"empty supabase ref":        {replace(`"supabaseRef":"abcdefghijklmnopqrst"`, `"supabaseRef":""`), setupcode.RefusalInvalid},
		"port as a float":           {replace(`"port":6543`, `"port":6543.5`), setupcode.RefusalInvalid},
		"port out of range":         {replace(`"port":6543`, `"port":70000`), setupcode.RefusalInvalid},
		"timeout of zero":           {replace(`"statementTimeoutMs":30000`, `"statementTimeoutMs":0`), setupcode.RefusalInvalid},
		"timeout over a day":        {replace(`"statementTimeoutMs":30000`, `"statementTimeoutMs":86400001`), setupcode.RefusalInvalid},
		"duplicate table":           {replace(`"write":["public.leads"]`, `"write":["public.leads","public.leads"]`), setupcode.RefusalInvalid},
		"pg_ schema":                {replace(`"public.leads"`, `"pg_toast.leads"`), setupcode.RefusalInvalid},
		"information_schema":        {replace(`"public.leads"`, `"information_schema.tables"`), setupcode.RefusalInvalid},
		"bad build":                 {replace(`"build":"0.5.0"`, `"build":"v0.5"`), setupcode.RefusalInvalid},
		"bad host":                  {replace(`"host":"aws-0-eu-central-1.pooler.supabase.com"`, `"host":"a b"`), setupcode.RefusalInvalid},
		"empty database":            {replace(`"database":"postgres"`, `"database":""`), setupcode.RefusalInvalid},
		"invalid date":              {replace(`"expiresAt":"2026-11-12T06:12:11Z"`, `"expiresAt":"2026-13-13T06:02:11Z"`), setupcode.RefusalInvalid},
		"fractional expiry":         {replace(`"expiresAt":"2026-11-12T06:12:11Z"`, `"expiresAt":"2026-11-13T06:02:11.5Z"`), setupcode.RefusalInvalid},
		"invalid utf-8":             {replace(`"database":"postgres"`, "\"database\":\"post\xffgres\""), setupcode.RefusalInvalid},
		"database with a NUL":       {replace(`"database":"postgres"`, `"database":"post\u0000gres"`), setupcode.RefusalInvalid},
		"database with DEL":         {replace(`"database":"postgres"`, `"database":"post\u007fgres"`), setupcode.RefusalInvalid},
		"database with a C1 char":   {replace(`"database":"postgres"`, `"database":"post\u0085gres"`), setupcode.RefusalInvalid},
		"database with bidi":        {replace(`"database":"postgres"`, `"database":"post\u202egres"`), setupcode.RefusalInvalid},
		"database with an isolate":  {replace(`"database":"postgres"`, `"database":"post\u2066gres"`), setupcode.RefusalInvalid},
		"database with zero width":  {replace(`"database":"postgres"`, `"database":"post\u200bgres"`), setupcode.RefusalInvalid},
		"trailing data":             {append(append([]byte{}, good...), []byte(" {}")...), setupcode.RefusalInvalid},
		// The last of duplicate keys would win in Go's decoder: a reader
		// that kept the first would see another code.
		"duplicate key":        {replace(`"kind":"INSTALL"`, `"kind":"UPGRADE","kind":"INSTALL"`), setupcode.RefusalInvalid},
		"duplicate same value": {replace(`"kind":"INSTALL"`, `"kind":"INSTALL","kind":"INSTALL"`), setupcode.RefusalInvalid},
		"duplicate format":     {replace(`"format":1`, `"format":2,"format":1`), setupcode.RefusalInvalid},
		"duplicate nested key": {replace(`"database":"postgres"`, `"database":"other","database":"postgres"`), setupcode.RefusalInvalid},
		// \u0066 is a JSON escape of "f": the same key once decoded.
		"duplicate escaped key":    {replace(`"prefix":`, "\"pre\\u0066ix\":\"evil\",\"prefix\":"), setupcode.RefusalInvalid},
		"duplicate escaped format": {replace(`"format":1`, "\"\\u0066ormat\":2,\"format\":1"), setupcode.RefusalInvalid},
		"duplicate verifier":       {replace(`"verifier":`, `"verifier":"x","verifier":`), setupcode.RefusalInvalid},
		"non-canonical verifier": {
			replace("AQIDBAUGBwgJCgsMDQ4PEA==", "AQIDBAUGBwgJCgsMDQ4PEB=="),
			setupcode.RefusalInvalid,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := setupcode.Decode(rawCode(t, c.payload))
			require.Error(t, err)
			require.Equal(t, c.refusal, refusalOf(t, err))
		})
	}
}

func TestDecodeRefusesBadBase64AndDeflate(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"not base64url":    "basalt-setup.1.ab+/",
		"not deflate":      "basalt-setup.1." + base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xff, 0xff}),
		"no payload":       "basalt-setup.1.",
		"padded base64url": "basalt-setup.1.AA==",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := setupcode.Decode(withCheck(body))
			require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err))
		})
	}
}

func TestDecodeCapsInput(t *testing.T) {
	t.Parallel()
	code, err := setupcode.Encode(validPayload(t))
	require.NoError(t, err)
	padded := code + strings.Repeat(" ", setupcode.MaxInputBytes)
	_, err = setupcode.Decode(padded)
	require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err), "refused before the whitespace is dropped")
	_, err = setupcode.Decode(code + strings.Repeat(" ", setupcode.MaxInputBytes-len(code)))
	require.NoError(t, err)
}

func TestDecodeRefusesTrailingDeflateData(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validPayload(t))
	require.NoError(t, err)
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	body := "basalt-setup.1." + base64.RawURLEncoding.EncodeToString(buf.Bytes())
	_, err = setupcode.Decode(withCheck(body))
	require.NoError(t, err, "the stream alone decodes")

	buf.WriteString("junk")
	body = "basalt-setup.1." + base64.RawURLEncoding.EncodeToString(buf.Bytes())
	_, err = setupcode.Decode(withCheck(body))
	require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err))
}

func TestDecodeCapsInflatedSize(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte(" "), setupcode.MaxPayloadBytes+1)
	_, err := setupcode.Decode(rawCode(t, big))
	require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err))
}

func TestDecodeAcceptsAnyKeyOrder(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	var generic map[string]any
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &generic))
	reordered, err := json.Marshal(generic) // map keys come out sorted
	require.NoError(t, err)
	require.NotEqual(t, raw, reordered)
	got, err := setupcode.Decode(rawCode(t, reordered))
	require.NoError(t, err)
	require.Equal(t, p, got)
}

func TestEncode(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	p.Agent.Read = nil // encodes as an empty list, never null
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	got, err := setupcode.Decode(code)
	require.NoError(t, err)
	require.Equal(t, []string{}, got.Agent.Read)

	bad := validPayload(t)
	bad.Prefix = "Bad"
	_, err = setupcode.Encode(bad)
	require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err))
}

func TestEncodeRefusesLongCode(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	p.Agent.Write, p.Agent.Read = nil, nil
	// Random-looking table names compress poorly: 2 x 64 of them exceed 1500.
	for i := range 64 {
		w, r := sha256.Sum256([]byte{'w', byte(i)}), sha256.Sum256([]byte{'r', byte(i)})
		p.Agent.Write = append(p.Agent.Write, fmt.Sprintf("public.t%x", w[:16]))
		p.Agent.Read = append(p.Agent.Read, fmt.Sprintf("public.t%x", r[:16]))
	}
	_, err := setupcode.Encode(p)
	require.ErrorIs(t, err, setupcode.ErrCodeTooLong)
}

func TestWrappedCopyDecodes(t *testing.T) {
	t.Parallel()
	code, err := setupcode.Encode(validPayload(t))
	require.NoError(t, err)
	var wrapped strings.Builder
	wrapped.WriteString("\n  ")
	for i, r := range code {
		if i > 0 && i%40 == 0 {
			wrapped.WriteString("\r\n\t ")
		}
		wrapped.WriteRune(r)
	}
	wrapped.WriteString(" \n")
	got, err := setupcode.Decode(wrapped.String())
	require.NoError(t, err)
	require.Equal(t, validPayload(t), got)
}

func TestFingerprint(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	require.Regexp(t, `^[0-9a-f]{4}( [0-9a-f]{4}){4}$`, p.Fingerprint())
	other := p
	other.Agent = &setupcode.Agent{}
	*other.Agent = *p.Agent
	other.Agent.Verifier = ""
	require.NotEqual(t, p.Fingerprint(), other.Fingerprint(), "the verifier is part of the fingerprint")
}

func TestRole(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	require.Equal(t, "basalt_agent_lead_bot", p.Role())
	p.Agent = nil
	require.Empty(t, p.Role())
}

// The fingerprint covers the whole code (owner decision, Nov 12): a code
// reposted with any field changed shows another fingerprint.
func TestFingerprintCoversTheWholeCode(t *testing.T) {
	t.Parallel()
	base := validPayload(t)
	require.NotNil(t, base.Agent)
	withAgent := func(change func(a *setupcode.Agent)) setupcode.Payload {
		p := base
		a := *base.Agent
		change(&a)
		p.Agent = &a
		return p
	}
	changed := map[string]setupcode.Payload{
		"write tables": withAgent(func(a *setupcode.Agent) { a.Write = append(slices.Clone(a.Write), "public.secrets") }),
		"read tables":  withAgent(func(a *setupcode.Agent) { a.Read = append(slices.Clone(a.Read), "public.secrets") }),
		"agent name":   withAgent(func(a *setupcode.Agent) { a.Name += "x" }),
		"timeout":      withAgent(func(a *setupcode.Agent) { a.StatementTimeoutMs++ }),
		"verifier":     withAgent(func(a *setupcode.Agent) { a.Verifier = "" }),
		"kind": func() setupcode.Payload {
			p := base
			p.Kind = setupcode.KindAgent
			if base.Kind == setupcode.KindAgent {
				p.Kind = setupcode.KindInstall
			}
			return p
		}(),
		"target": func() setupcode.Payload {
			p, t := base, *base.Target
			t.Database += "x"
			p.Target = &t
			return p
		}(),
		"expiry": func() setupcode.Payload { p := base; p.ExpiresAt = "2026-01-01T00:00:00Z"; return p }(),
	}
	seen := map[string]string{base.Fingerprint(): "base"}
	for name, p := range changed {
		fp := p.Fingerprint()
		require.NotContains(t, seen, fp, "%s keeps the fingerprint of %s", name, seen[fp])
		seen[fp] = name
	}
}

// An agent code without a verifier (kept password) still gets a fingerprint
// of its payload, and the decoded code gives the code-maker's fingerprint
// whatever key order the code was written in (status returns the one
// init --remote saved).
func TestFingerprintOfTheDecodedCode(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	a := *p.Agent
	a.Verifier = ""
	p.Agent = &a
	p.Kind = setupcode.KindAgent
	other := p
	other.SetupID = validPayload(t).SetupID
	b := *p.Agent
	b.Write = append(slices.Clone(b.Write), "public.secrets")
	other.Agent = &b
	require.NotEqual(t, p.Fingerprint(), other.Fingerprint(), "no verifier: the tables still count")

	// Keys in reverse order: the same payload, the same fingerprint.
	var m map[string]any
	js, err := json.Marshal(p)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(js, &m))
	keys := []string{"expiresAt", "agent", "build", "guard", "target", "prefix", "kind", "setupId", "format"}
	var sb strings.Builder
	sb.WriteString("{")
	for i, k := range keys {
		if _, ok := m[k]; !ok {
			continue
		}
		v, err := json.Marshal(m[k])
		require.NoError(t, err)
		if i > 0 && sb.Len() > 1 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "%q:%s", k, v)
	}
	sb.WriteString("}")
	decoded, err := setupcode.Decode(rawCode(t, []byte(sb.String())))
	require.NoError(t, err)
	require.Equal(t, p.Fingerprint(), decoded.Fingerprint())
}

// A connect-only code relaxes ROLE_MISSING for its recovery AGENT code
// only: an INSTALL still refuses an existing role, and an AGENT code with a
// target still needs its role.
func TestConnectOnlyRoleRules(t *testing.T) {
	t.Parallel()
	base := validPayload(t)
	role := base.Role()
	install := base
	install.Target = nil
	require.Equal(t, setupcode.RefusalRoleExists, refusalOf(t, setupcode.CheckDatabase(install, setupcode.Database{Roles: []string{role}})))
	withTarget := base
	withTarget.Kind = setupcode.KindAgent
	require.Equal(t, setupcode.RefusalRoleMissing, refusalOf(t, setupcode.CheckDatabase(withTarget, setupcode.Database{})))
	recovery := withTarget
	recovery.Target = nil
	require.NoError(t, setupcode.CheckDatabase(recovery, setupcode.Database{}))
}
