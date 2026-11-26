package guard_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// localApproval is a plugin approval detail of a local wire.detect entry in
// same-user mode with no known signer, for the given agent roles.
func localApproval(agents ...string) guardmodel.PluginApprovalDetail {
	return guardmodel.PluginApprovalDetail{
		Agents: agents, Name: "local-ner", Instance: "client_x", Version: "0.3.1",
		ManifestSHA256: strings.Repeat("a1", 32), Hooks: []string{"wire.detect"}, Roles: []string{"VALUE"},
		Egress: []string{}, Endpoint: guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointLocal},
		Isolation: &guardmodel.PluginIsolation{Files: guardmodel.PluginFilesNone, Network: guardmodel.PluginNetworkNotEnforced},
		Signer:    guardmodel.PluginSignerUnknown,
	}
}

func intPtr(v int) *int { return &v }

// signPlugin signs a plugin approval's binding text with p.
func signPlugin(t *testing.T, p *passkeytest.Authenticator, a guardmodel.PluginApproval) guardmodel.PluginApprovalResponse {
	t.Helper()
	as, err := p.Sign(passkeytest.Challenge(a.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return guardmodel.PluginApprovalResponse{ApprovalID: a.ID, Assertion: as}
}

// openRaw calls open_plugin_approval as an agent could on its own
// connection, with raw JSON.
func openRaw(q guard.Querier, detail, settings string) error {
	// Plain SQL: the guard function called with raw input, as an agent could.
	_, err := q.Exec(context.Background(), `SELECT * FROM basalt_meta.open_plugin_approval($1::jsonb, $2::jsonb)`, detail, settings)
	return err
}

func requireGuardDetail(t *testing.T, err error, code guard.Code, detail string) {
	t.Helper()
	requireCode(t, err, code)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Equal(t, detail, pg.Detail)
}

func ledgerKinds(t *testing.T, d *guardtest.DB, role, kind string) int {
	t.Helper()
	return count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE agent = $1 AND kind = $2`, role, kind)
}

func approvalStatus(t *testing.T, q guard.Querier, id uuid.UUID) string {
	t.Helper()
	return scalarOf[string](t, q, `SELECT status FROM basalt_meta.agent_plugin_approvals WHERE approval_id = $1`, id)
}

// Open, sign with the person's passkey, relay by an agent not named: each
// named agent's ledger gets PLUGIN_APPROVED with a detail that names no
// agent, and only the opener sees the texts that list them.
func TestPluginApprovalRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "product_a", leads, nil)
	b := d.NewAgent(t, "product_b", leads, nil)
	c := d.NewAgent(t, "client_x", leads, nil)
	p := person(t, d)

	settings := guardmodel.PluginSettings{Config: json.RawMessage(`{"threshold": 0.60, "max": 1e3}`), TimeoutMs: intPtr(300)}
	opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(b.Name, a.Name), settings)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), opened.ExpiresAt, time.Minute)
	require.Equal(t, `{"config": {"max": 1000, "threshold": 0.60}, "timeoutMs": 300}`, opened.SettingsText)
	var binding map[string]any
	require.NoError(t, json.Unmarshal([]byte(opened.BindingText), &binding))
	require.Equal(t, "PLUGIN", binding["kind"])
	require.Equal(t, opened.ID.String(), binding["approvalId"])
	require.Equal(t, a.Name, binding["requestedBy"])
	require.Equal(t, []any{a.Name, b.Name}, binding["agents"], "sorted by the client, kept by Postgres")
	sum := sha256.Sum256([]byte(opened.SettingsText))
	require.Equal(t, hex.EncodeToString(sum[:]), binding["settingsSha256"])
	require.NotContains(t, binding, "change", "no earlier signed approval")

	// Only the opener's ledger records the request, and it names no agent.
	require.Equal(t, 1, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApprovalPending)))
	require.Zero(t, ledgerKinds(t, d, b.Role, string(guardmodel.PluginApprovalPending)))
	pending := scalarOf[string](t, a.Conn, `SELECT detail::text FROM basalt_meta.agent_ledger WHERE kind = 'PLUGIN_APPROVAL_PENDING'`)
	require.NotContains(t, pending, d.Names.Prefix, "the pending detail names no agent role")
	require.NotContains(t, pending, `"agents"`)

	// The view: the opener sees the texts, a named agent only the status
	// and detail, an agent not named nothing.
	recA, ok, err := guard.ReadPluginApproval(ctx, a.Conn, opened.ID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, opened.BindingText, recA.BindingText)
	require.Equal(t, opened.SettingsText, recA.SettingsText)
	require.Equal(t, guardmodel.PluginApprovalStatusPending, recA.Status)
	recB, ok, err := guard.ReadPluginApproval(ctx, b.Conn, opened.ID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, recB.BindingText)
	require.Empty(t, recB.SettingsText)
	require.True(t, recB.NamesCaller)
	rowB := scalarOf[string](t, b.Conn, `SELECT row_to_json(v)::text FROM basalt_meta.agent_plugin_approvals v`)
	require.NotContains(t, rowB, d.Names.Prefix, "a named agent that did not open it sees no role name")
	_, ok, err = guard.ReadPluginApproval(ctx, c.Conn, opened.ID)
	require.NoError(t, err)
	require.False(t, ok, "an agent neither named nor the opener sees nothing")

	resp := signPlugin(t, p, opened)
	at, err := guard.SubmitPluginApproval(ctx, c.Conn, resp)
	require.NoError(t, err, "any agent role relays the person's signature")
	require.WithinDuration(t, time.Now(), at, time.Minute)

	for _, role := range []string{a.Role, b.Role} {
		require.Equal(t, 1, ledgerKinds(t, d, role, string(guardmodel.PluginApproved)), role)
	}
	require.Zero(t, ledgerKinds(t, d, c.Role, string(guardmodel.PluginApproved)))
	var approved map[string]any
	require.NoError(t, json.Unmarshal([]byte(scalarOf[string](t, b.Conn,
		`SELECT detail::text FROM basalt_meta.agent_ledger WHERE kind = 'PLUGIN_APPROVED'`)), &approved))
	require.NotContains(t, approved, "agents")
	require.NotContains(t, approved, "expiresAt")
	require.NotContains(t, approved, "requestedBy")
	require.Equal(t, base64.RawURLEncoding.EncodeToString(p.ID), approved["credentialId"])
	bsum := sha256.Sum256([]byte(opened.BindingText))
	require.Equal(t, hex.EncodeToString(bsum[:]), approved["bindingSha256"])
	require.Equal(t, binding["settingsSha256"], approved["settingsSha256"])
	approvedText := scalarOf[string](t, b.Conn, `SELECT detail::text FROM basalt_meta.agent_ledger WHERE kind = 'PLUGIN_APPROVED'`)
	require.NotContains(t, approvedText, d.Names.Prefix)

	recs, err := guard.ReadPluginApprovals(ctx, b.Conn)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	r := recs[0]
	require.Equal(t, opened.ID, r.ApprovalID)
	require.Equal(t, guardmodel.PluginApprovalStatusApproved, r.Status)
	require.NotNil(t, r.ApprovedAt)
	require.False(t, r.Ended())
	want := localApproval()
	require.Equal(t, guardmodel.PluginApprovalBound{
		Name: want.Name, Instance: want.Instance, Version: want.Version, ManifestSHA256: want.ManifestSHA256,
		SettingsSHA256: hex.EncodeToString(sum[:]), Hooks: want.Hooks, Roles: want.Roles, Egress: want.Egress,
		Endpoint: want.Endpoint, Isolation: want.Isolation, Signer: want.Signer,
	}, r.Bound)
	recs, err = guard.ReadPluginApprovals(ctx, c.Conn)
	require.NoError(t, err)
	require.Empty(t, recs)

	_, err = guard.SubmitPluginApproval(ctx, a.Conn, resp)
	requireGuardDetail(t, err, guard.CodeApprovalInvalid, guard.DetailAlreadyApproved)
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, guardmodel.PluginApprovalResponse{ApprovalID: uuid.Must(uuid.NewV7()), Assertion: resp.Assertion})
	requireGuardDetail(t, err, guard.CodeApprovalInvalid, guard.DetailApprovalNotFound)
	st, err := guard.VerifyChain(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, st.Intact)
}

// An agent role cannot produce a PLUGIN_APPROVED row: not through any
// function it may call, not with a made-up assertion, a signature over
// another binding or its own key, and not by writing the tables.
func TestAgentCannotForgePluginApproved(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	// A held write of the same agent, for the cross-kind case below.
	held, _ := previewAndHold(t, a.Conn, newRun(t, a, "remove the spam lead"), `DELETE FROM public.leads WHERE id = $1`, []any{3}, []string{})
	ctx := context.Background()
	opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	approvedDetail := `{"approvalId": "` + opened.ID.String() + `", "credentialId": "AAAA", "bindingSha256": "` +
		strings.Repeat("0", 64) + `", "name": "local-ner", "instance": "client_x", "version": "0.3.1", "manifestSha256": "` +
		strings.Repeat("a1", 32) + `", "settingsSha256": "` + strings.Repeat("0", 64) + `", "hooks": ["wire.detect"], ` +
		`"roles": ["VALUE"], "egress": [], "endpoint": {"kind": "LOCAL"}, "isolation": {"files": "NONE", "network": "NOT_ENFORCED"}, "signer": "UNKNOWN"}`

	t.Run("record_plugin_event refuses both approval kinds", func(t *testing.T) {
		for _, kind := range []guardmodel.PluginEventKind{guardmodel.PluginApproved, guardmodel.PluginApprovalPending} {
			requireCode(t, recordRaw(t, a.Conn, string(kind), approvedDetail), guard.CodeLedgerInputInvalid)
		}
	})
	t.Run("record_event refuses them", func(t *testing.T) {
		for _, kind := range []guardmodel.PluginEventKind{guardmodel.PluginApproved, guardmodel.PluginApprovalPending} {
			_, err := a.Conn.Exec(ctx, `SELECT basalt_meta.record_event($1, NULL, $2::jsonb)`, string(kind), approvedDetail)
			requireCode(t, err, guard.CodeLedgerInputInvalid)
		}
	})
	t.Run("internal functions and the tables are closed to agents", func(t *testing.T) {
		for _, sql := range []string{
			`SELECT basalt_meta._append(session_user, NULL, 'PLUGIN_APPROVED', NULL, NULL, NULL, NULL, NULL, NULL, '{}'::jsonb)`,
			`SELECT basalt_meta._verify_assertion('\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea)`,
			`SELECT basalt_meta._plugin_approval_binding(gen_random_uuid(), now(), session_user, '{}'::jsonb, '')`,
			`SELECT basalt_meta._check_plugin_approval_agents('[]'::jsonb)`,
			`UPDATE basalt_meta.plugin_approvals SET status = 'APPROVED'`,
			`SELECT count(*) FROM basalt_meta.plugin_approvals`,
			`INSERT INTO basalt_meta.plugin_approval_ends VALUES (gen_random_uuid(), session_user, now())`,
			`DELETE FROM basalt_meta.plugin_approval_ends`,
			`INSERT INTO basalt_meta.ledger (agent, kind) VALUES (session_user, 'PLUGIN_APPROVED')`,
			`SELECT basalt_meta.register_passkey('\x01'::bytea, '\x01'::bytea, '\x01'::bytea, 'x', 'https://x', 'x', NULL)`,
		} {
			_, err := a.Conn.Exec(ctx, sql)
			require.Equal(t, "42501", guardtest.SQLState(err), "%s: %v", sql, err)
		}
	})
	t.Run("made-up assertions", func(t *testing.T) {
		forger, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		forger.ID = p.ID
		_, err = guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, forger, opened))
		requireInvalid(t, err, "bad passkey signature")

		stranger, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		_, err = guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, stranger, opened))
		requireInvalid(t, err, "unknown passkey")

		as, err := p.Sign(passkeytest.Challenge(opened.BindingText+" "), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = guard.SubmitPluginApproval(ctx, a.Conn, guardmodel.PluginApprovalResponse{ApprovalID: opened.ID, Assertion: as})
		requireInvalid(t, err, "client data does not match")

		as, err = p.Sign(passkeytest.Challenge(opened.BindingText), passkeytest.FlagUP, nil)
		require.NoError(t, err)
		_, err = guard.SubmitPluginApproval(ctx, a.Conn, guardmodel.PluginApprovalResponse{ApprovalID: opened.ID, Assertion: as})
		requireInvalid(t, err, "verification required")

		_, err = guard.SubmitPluginApproval(ctx, a.Conn, guardmodel.PluginApprovalResponse{ApprovalID: opened.ID})
		requireInvalid(t, err, "missing a field")
	})
	t.Run("a held write's signature does not sign a plugin approval", func(t *testing.T) {
		_, err := guard.SubmitPluginApproval(ctx, a.Conn, guardmodel.PluginApprovalResponse{ApprovalID: opened.ID, Assertion: sign(t, p, held, nil)})
		requireInvalid(t, err, "client data does not match")
		// Nor does a plugin approval's signature apply to the held write.
		_, err = guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, signPlugin(t, p, opened).Assertion)
		requireInvalid(t, err, "client data does not match")
	})

	require.Zero(t, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'PLUGIN_APPROVED'`))
	require.Equal(t, string(guardmodel.PluginApprovalStatusPending), approvalStatus(t, a.Conn, opened.ID))
	// The person's own signature still works afterwards: the forgeries
	// changed nothing.
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, p, opened))
	require.NoError(t, err)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'PLUGIN_APPROVED'`))
}

// A signature over one approval's binding cannot sign another, even of the
// same entry with the same detail.
func TestPluginSignatureNotReplayable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	p := person(t, d)
	one, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	other := localApproval(a.Name)
	other.Instance = "default"
	two, err := guard.OpenPluginApproval(ctx, a.Conn, other, guardmodel.PluginSettings{})
	require.NoError(t, err)
	resp := signPlugin(t, p, one)
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, guardmodel.PluginApprovalResponse{ApprovalID: two.ID, Assertion: resp.Assertion})
	requireInvalid(t, err, "client data does not match")
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, resp)
	require.NoError(t, err)
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, guardmodel.PluginApprovalResponse{ApprovalID: two.ID, Assertion: resp.Assertion})
	requireInvalid(t, err, "client data does not match")
	require.Equal(t, string(guardmodel.PluginApprovalStatusPending), approvalStatus(t, a.Conn, two.ID))
}

// Passkeys are per database: one registered on another database cannot
// sign an approval here.
func TestPluginApprovalPasskeyOfAnotherDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	elsewhere := guardtest.New(t).WithDemo(t)
	elsewhere.NewAgent(t, "bot", leads, nil)
	p := person(t, elsewhere)
	opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, p, opened))
	requireInvalid(t, err, "unknown passkey")
	require.Zero(t, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApproved)))
}

// Every agent in agents must name an agent role of this database: not an
// unknown name, nor a role that is the agents group, a superuser, the
// guard role, a plain role or an agent of another database's guard.
func TestOpenRefusesUnknownAgent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	other := guardtest.New(t).WithDemo(t)
	o := other.NewAgent(t, "bot", leads, nil)
	plain := d.Names.Prefix + "_plain"
	d.Exec(t, `CREATE ROLE `+plain+` LOGIN`)
	superuser := scalarOf[string](t, d.Admin, `SELECT current_user::text`)
	require.True(t, scalarOf[bool](t, d.Admin, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`))
	// Names are agent:<name>, mapped to roles from the guard's record: a
	// name with no record, and a recorded name whose role is not an agent
	// role of this database (here, of the agents group, a superuser, the
	// guard role, a plain role, or an agent of another database's guard).
	for i, role := range []string{d.Names.Agents(), superuser, d.Names.Guard(), plain, o.Role} {
		d.Exec(t, `INSERT INTO basalt_meta.agent_names (role, name) VALUES ($1, $2)`, role, fmt.Sprintf("fake_%d", i))
	}
	for _, name := range []string{"agent:nobody", "agent:fake_0", "agent:fake_1", "agent:fake_2", "agent:fake_3", "agent:fake_4"} {
		_, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name, name), guardmodel.PluginSettings{})
		requireGuardDetail(t, err, guard.CodeNotAllowed, guard.DetailUnknownAgent)
		require.NotContains(t, err.Error(), name, "the refusal never names the agent")
	}
	require.Zero(t, count(t, d.Admin, `SELECT count(*)::int FROM basalt_meta.plugin_approvals`))
	require.Zero(t, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApprovalPending)))
	// The admin is not an agent role and cannot open one.
	_, err := guard.OpenPluginApproval(ctx, d.Admin, localApproval(a.Name), guardmodel.PluginSettings{})
	requireCode(t, err, guard.CodeNotAllowed)
}

// The detail and settings are checked against the binding schema; each
// refusal is BS008, names the rule, and writes nothing.
func TestOpenRefusesBadDetail(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	b := d.NewAgent(t, "helper", leads, nil)
	base := func() map[string]any {
		raw, err := json.Marshal(localApproval(a.Name))
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		return m
	}
	for name, mutate := range map[string]func(m map[string]any){
		"no agents":             func(m map[string]any) { m["agents"] = []string{} },
		"agents unsorted":       func(m map[string]any) { m["agents"] = []string{b.Name, a.Name} },
		"agent twice":           func(m map[string]any) { m["agents"] = []string{a.Name, a.Name} },
		"agent not a role name": func(m map[string]any) { m["agents"] = []string{"Bot One"} },
		"no signer":             func(m map[string]any) { delete(m, "signer") },
		"signer unknown value":  func(m map[string]any) { m["signer"] = "TRUSTED" },
		"unknown with key id":   func(m map[string]any) { m["signerKeyId"] = "jNZPxNG5htlwfhg4ZgknAA" },
		"known without key id":  func(m map[string]any) { m["signer"] = "KNOWN" },
		"model":                 func(m map[string]any) { m["model"] = map[string]any{"name": "m", "version": "1"} },
		"settingsSha256 given":  func(m map[string]any) { m["settingsSha256"] = strings.Repeat("0", 64) },
		"kind given":            func(m map[string]any) { m["kind"] = "PLUGIN" },
		"change given":          func(m map[string]any) { m["change"] = map[string]any{} },
		"requestedBy given":     func(m map[string]any) { m["requestedBy"] = b.Role },
		"detect without roles":  func(m map[string]any) { delete(m, "roles") },
		"detect empty roles":    func(m map[string]any) { m["roles"] = []string{} },
		"roles unsorted":        func(m map[string]any) { m["roles"] = []string{"VALUE", "NAME_CUE"} },
		"hooks unsorted":        func(m map[string]any) { m["hooks"] = []string{"wire.detect", "feed.observe"} },
		"egress unsorted":       func(m map[string]any) { m["egress"] = []string{"b.example:443", "a.example:443"} },
		"local no isolation":    func(m map[string]any) { delete(m, "isolation") },
		"isolation OS_USER": func(m map[string]any) {
			m["isolation"] = map[string]any{"files": "OS_USER", "network": "ENFORCED"}
		},
		"version free text": func(m map[string]any) { m["version"] = "1.0 for other-agent" },
		"over 4 KiB": func(m map[string]any) {
			var e []string
			for i := range 250 {
				e = append(e, fmt.Sprintf("host%03d.example:443", i))
			}
			m["egress"] = e
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(m)
			raw, err := json.Marshal(m)
			require.NoError(t, err)
			requireCode(t, openRaw(a.Conn, string(raw), `{}`), guard.CodeLedgerInputInvalid)
		})
	}
	good, err := json.Marshal(base())
	require.NoError(t, err)
	for name, settings := range map[string]string{
		"null":                  `null`,
		"an array":              `[]`,
		"unknown key":           `{"enabled": true}`,
		"agents key":            `{"agents": ["x"]}`,
		"config not an object":  `{"config": [1]}`,
		"auth on a local entry": `{"auth": {"credentialFile": "/etc/x"}}`,
		"timeout too small":     `{"timeoutMs": 49}`,
		"timeout fractional":    `{"timeoutMs": 300.5}`,
		"timeout a string":      `{"timeoutMs": "300"}`,
		"confidence over one":   `{"minConfidence": 1.01}`,
		"confidence below zero": `{"minConfidence": -0.1}`,
		"settings over 64 KiB":  `{"config": {"x": "` + strings.Repeat("a", 70000) + `"}}`,
	} {
		t.Run("settings "+name, func(t *testing.T) {
			requireCode(t, openRaw(a.Conn, string(good), settings), guard.CodeLedgerInputInvalid)
		})
	}
	for _, detail := range []string{`null`, `[]`, `"x"`, `{}`} {
		requireCode(t, openRaw(a.Conn, detail, `{}`), guard.CodeLedgerInputInvalid)
	}
	require.Zero(t, count(t, d.Admin, `SELECT count(*)::int FROM basalt_meta.plugin_approvals`))
	require.Zero(t, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApprovalPending)))
	require.NoError(t, openRaw(a.Conn, string(good), `{"timeoutMs": 300.0, "minConfidence": 0.60}`), "the base passes")
	require.Equal(t, `{"timeoutMs": 300, "minConfidence": 0.6}`, scalarOf[string](t, d.Admin,
		`SELECT settings_text FROM basalt_meta.plugin_approvals`), "the two numbers by value")
}

// Opening a new approval for the same (name, instance) cancels the earlier
// pending one, which can then no longer be signed. Another instance is not
// touched.
func TestSecondPendingCancelsFirst(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	b := d.NewAgent(t, "helper", leads, nil)
	p := person(t, d)
	first, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	other := localApproval(a.Name)
	other.Instance = "default"
	otherOpened, err := guard.OpenPluginApproval(ctx, a.Conn, other, guardmodel.PluginSettings{})
	require.NoError(t, err)
	// Another agent of the database opens the same entry for itself.
	second, err := guard.OpenPluginApproval(ctx, b.Conn, localApproval(b.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)

	require.Equal(t, string(guardmodel.PluginApprovalStatusCancelled), approvalStatus(t, a.Conn, first.ID))
	require.Equal(t, string(guardmodel.PluginApprovalStatusPending), approvalStatus(t, a.Conn, otherOpened.ID))
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, p, first))
	requireGuardDetail(t, err, guard.CodeApprovalInvalid, guard.DetailApprovalCancelled)
	require.Zero(t, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApproved)))

	// For a, the newest approval naming it is the cancelled one.
	recs, err := guard.ReadPluginApprovals(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, recs, 2)
	require.Equal(t, first.ID, recs[0].ApprovalID)
	require.Equal(t, guardmodel.PluginApprovalStatusCancelled, recs[0].Status)

	_, err = guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, p, second))
	require.NoError(t, err)
	require.Equal(t, 1, ledgerKinds(t, d, b.Role, string(guardmodel.PluginApproved)))
}

// At most 8 unexpired pending approvals per database: the ninth is
// refused; re-opening one of the eight, an expired, a cancelled or a
// signed one frees nothing it should not.
func TestPendingCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	p := person(t, d)
	instance := func(i int) guardmodel.PluginApprovalDetail {
		x := localApproval(a.Name)
		x.Instance = fmt.Sprintf("i%d", i)
		return x
	}
	opened := make([]guardmodel.PluginApproval, 0, 8)
	for i := range 8 {
		o, err := guard.OpenPluginApproval(ctx, a.Conn, instance(i), guardmodel.PluginSettings{})
		require.NoError(t, err)
		opened = append(opened, o)
	}
	_, err := guard.OpenPluginApproval(ctx, a.Conn, instance(8), guardmodel.PluginSettings{})
	requireGuardDetail(t, err, guard.CodeNotAllowed, guard.DetailTooManyPending)
	require.Equal(t, 8, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApprovalPending)), "the refusal writes nothing")

	// Re-opening one of the eight replaces it.
	_, err = guard.OpenPluginApproval(ctx, a.Conn, instance(0), guardmodel.PluginSettings{})
	require.NoError(t, err)
	_, err = guard.OpenPluginApproval(ctx, a.Conn, instance(8), guardmodel.PluginSettings{})
	requireGuardDetail(t, err, guard.CodeNotAllowed, guard.DetailTooManyPending)

	// An expired one does not count.
	d.Exec(t, `UPDATE basalt_meta.plugin_approvals SET expires_at = now() - interval '1 second' WHERE approval_id = $1`, opened[1].ID)
	_, err = guard.OpenPluginApproval(ctx, a.Conn, instance(8), guardmodel.PluginSettings{})
	require.NoError(t, err)
	_, err = guard.OpenPluginApproval(ctx, a.Conn, instance(9), guardmodel.PluginSettings{})
	requireGuardDetail(t, err, guard.CodeNotAllowed, guard.DetailTooManyPending)

	// A signed one does not count.
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, p, opened[2]))
	require.NoError(t, err)
	_, err = guard.OpenPluginApproval(ctx, a.Conn, instance(9), guardmodel.PluginSettings{})
	require.NoError(t, err)
	require.Equal(t, 8, count(t, d.Admin, `SELECT count(*)::int FROM basalt_meta.plugin_approvals
		WHERE status = 'PENDING' AND expires_at > now()`))
}

// A pending approval expires 24 hours after it is opened: the view says
// EXPIRED and the relay refuses it.
func TestPendingExpires(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	p := person(t, d)
	opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	require.Equal(t, 24*time.Hour, scalarOf[time.Duration](t, d.Admin,
		`SELECT expires_at - opened_at FROM basalt_meta.plugin_approvals WHERE approval_id = $1`, opened.ID))
	resp := signPlugin(t, p, opened)
	d.Exec(t, `UPDATE basalt_meta.plugin_approvals SET expires_at = now() - interval '1 second'`)
	require.Equal(t, string(guardmodel.PluginApprovalStatusExpired), approvalStatus(t, a.Conn, opened.ID))
	_, err = guard.SubmitPluginApproval(ctx, a.Conn, resp)
	requireCode(t, err, guard.CodeApprovalExpired)
	require.Zero(t, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApproved)))
	recs, err := guard.ReadPluginApprovals(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.Equal(t, guardmodel.PluginApprovalStatusExpired, recs[0].Status)
}

// A PLUGIN_DISABLED written after the approval was signed ends it for the
// agent that wrote it, and the end outlives the ledger row. A disable of
// another instance, or before the signature, ends nothing.
func TestDisableEndsApproval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	b := d.NewAgent(t, "helper", leads, nil)
	p := person(t, d)
	entry := guardmodel.PluginDetail{
		Name: "local-ner", Instance: "client_x", Version: "0.3.1", ManifestSHA256: strings.Repeat("a1", 32),
		Signer: guardmodel.PluginSignerUnknown, Hooks: []string{"wire.detect"}, Roles: []string{"VALUE"}, Egress: []string{},
		Endpoint:  guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointLocal},
		Isolation: &guardmodel.PluginIsolation{Files: guardmodel.PluginFilesNone, Network: guardmodel.PluginNetworkNotEnforced},
	}
	opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name, b.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	// Disabled while pending: the signature afterwards is not ended.
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginDisabled, entry))
	_, err = guard.SubmitPluginApproval(ctx, b.Conn, signPlugin(t, p, opened))
	require.NoError(t, err)
	rec, _, err := guard.ReadPluginApproval(ctx, a.Conn, opened.ID)
	require.NoError(t, err)
	require.False(t, rec.Ended())

	otherInstance := entry
	otherInstance.Instance = "default"
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginDisabled, otherInstance))
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, entry))
	rec, _, err = guard.ReadPluginApproval(ctx, a.Conn, opened.ID)
	require.NoError(t, err)
	require.False(t, rec.Ended())

	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginDisabled, entry))
	recs, err := guard.ReadPluginApprovals(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.True(t, recs[0].Ended(), "a's disable ends it for a")
	require.Equal(t, guardmodel.PluginApprovalStatusApproved, recs[0].Status)
	recs, err = guard.ReadPluginApprovals(ctx, b.Conn)
	require.NoError(t, err)
	require.False(t, recs[0].Ended(), "and not for b")
	endedAt := *scalarOf[*time.Time](t, a.Conn, `SELECT ended_at FROM basalt_meta.agent_plugin_approvals`)
	// A second disable keeps the first end.
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginDisabled, entry))
	require.Equal(t, endedAt, *scalarOf[*time.Time](t, a.Conn, `SELECT ended_at FROM basalt_meta.agent_plugin_approvals`))

	// Retention deletes the ledger rows after a year; the end stays.
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '400 days')`)
	require.Zero(t, ledgerKinds(t, d, a.Role, string(guardmodel.PluginDisabled)))
	recs, err = guard.ReadPluginApprovals(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, recs[0].Ended())
	require.Equal(t, guardmodel.PluginApprovalStatusApproved, recs[0].Status, "a signed approval never expires")
}

// pluginVector is one binding of api/plugin/approval/vectors.json.
type pluginVector struct {
	Name     string `json:"name"`
	Binding  string `json:"binding"`
	Settings string `json:"settings"`
}

func pluginVectors(t *testing.T) map[string]pluginVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "plugin", "approval", "vectors.json"))
	require.NoError(t, err)
	var doc struct {
		Vectors []pluginVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	out := map[string]pluginVector{}
	for _, v := range doc.Vectors {
		out[v.Name] = v
	}
	return out
}

// The binding and settings texts open_plugin_approval returns are the
// contract's vectors byte for byte, once the values only Postgres chooses
// (the id, the expiry and the database's name) are those of the vector.
// change is built from a real earlier signed approval, and the settings go
// in as written in engine.json (1e3, 0.60).
func TestBindingBuiltByPostgres(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "product_a", leads, nil)
	b := d.NewAgent(t, "product_b", leads, nil)
	c := d.NewAgent(t, "client_x", leads, nil)
	p := person(t, d)
	dbName := scalarOf[string](t, d.Admin, `SELECT current_database()::text`)
	vectors := pluginVectors(t)

	// asVector puts the vector's id, expiry and database into the
	// texts Postgres returned, and compares.
	asVector := func(t *testing.T, name string, o guardmodel.PluginApproval) {
		t.Helper()
		v := vectors[name]
		var want struct {
			ApprovalID string `json:"approvalId"`
			ExpiresAt  string `json:"expiresAt"`
		}
		require.NoError(t, json.Unmarshal([]byte(v.Binding), &want))
		var got map[string]any
		require.NoError(t, json.Unmarshal([]byte(o.BindingText), &got))
		text := strings.NewReplacer(
			`"approvalId": "`+o.ID.String()+`"`, `"approvalId": "`+want.ApprovalID+`"`,
			`"expiresAt": "`+got["expiresAt"].(string)+`"`, `"expiresAt": "`+want.ExpiresAt+`"`,
			`"store": {"kind": "POSTGRES", "name": "`+dbName+`"}`, `"store": {"kind": "POSTGRES", "name": "app"}`,
		).Replace(o.BindingText)
		require.Equal(t, v.Binding, text, name)
		require.Equal(t, v.Settings, o.SettingsText, name)
		require.Regexp(t, `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`, got["expiresAt"])
	}
	open := func(t *testing.T, q guard.Querier, detail guardmodel.PluginApprovalDetail, settings string) guardmodel.PluginApproval {
		t.Helper()
		var s guardmodel.PluginSettings
		require.NoError(t, json.Unmarshal([]byte(settings), &s))
		o, err := guard.OpenPluginApproval(ctx, q, detail, s)
		require.NoError(t, err)
		return o
	}

	t.Run("level 1", func(t *testing.T) {
		asVector(t, "level-1-known-local", open(t, a.Conn, guardmodel.PluginApprovalDetail{
			Agents: []string{a.Name, b.Name}, Name: "slack-notify", Instance: "default", Version: "1.0.0",
			ManifestSHA256: strings.Repeat("5e", 32), Hooks: []string{"approval.deliver", "feed.observe"},
			Egress: []string{"slack.com:443"}, Endpoint: guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointLocal},
			Isolation: &guardmodel.PluginIsolation{Files: guardmodel.PluginFilesNone, Network: guardmodel.PluginNetworkNotEnforced},
			Signer:    guardmodel.PluginSignerKnown, SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA",
		}, `{"timeoutMs": 2000, "config": {"channel": "ops-alerts"}}`))
	})
	acme := guardmodel.PluginApprovalDetail{
		Agents: []string{a.Name}, Name: "acme-ner", Instance: "default", Version: "1.4.0",
		ManifestSHA256: strings.Repeat("3f", 32), Hooks: []string{"wire.detect"}, Roles: []string{"NAME_CUE", "VALUE"},
		Egress: []string{"ner.acme.example:443"}, Endpoint: guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointRemote, Host: "ner.acme.example:443"},
		Signer: guardmodel.PluginSignerUnknown,
	}
	const acmeSettings = `{"config": {"languages": ["en", "id"]}, "auth": {"credentialFile": "/etc/basalt/plugins/acme-ner.token"}, "timeoutMs": 2000}`
	t.Run("level 2, then turned on again", func(t *testing.T) {
		first := open(t, a.Conn, acme, acmeSettings)
		asVector(t, "level-2-unknown-remote", first)
		_, err := guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, p, first))
		require.NoError(t, err)
		asVector(t, "change-turned-on-again", open(t, a.Conn, acme, acmeSettings))
	})
	t.Run("level 3, settings as engine.json holds them", func(t *testing.T) {
		asVector(t, "level-3-unknown-local", open(t, b.Conn, localApproval(b.Name),
			`{"minConfidence": 0.60, "timeoutMs": 300, "config": {"threshold": 0.60, "max": 1e3, "note": "tab\there é", "a": null}}`))
	})
	t.Run("a change", func(t *testing.T) {
		before := localApproval(a.Name)
		before.Instance = "default"
		earlier := open(t, a.Conn, before, `{"config": {"languages": ["en", "id"]}, "timeoutMs": 500}`)
		_, err := guard.SubmitPluginApproval(ctx, a.Conn, signPlugin(t, p, earlier))
		require.NoError(t, err)
		after := before
		after.Agents = []string{c.Name, a.Name}
		after.Version, after.ManifestSHA256 = "0.4.0", strings.Repeat("b2", 32)
		after.Roles = []string{"VALUE", "NAME_CUE"}
		after.Egress = []string{"models.acme.example:443"}
		asVector(t, "change-unknown-local", open(t, a.Conn, after, `{"config": {"languages": ["en"]}, "timeoutMs": 500}`))
	})
}

// A guard at version 4 has no plugin approvals; the upgrade adds them.
// Version 5's SQL runs again over itself, PUBLIC can run none of its
// functions, and agents keep exactly their grants. Version 10 replaces some
// of them, so it runs again after, as an upgrade would. The chain is not
// checked: rows hashed before version 10 do not verify after it (clean
// state).
func TestPluginApprovalsMigration(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, 4)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	_, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.Error(t, err)
	_, err = guard.ReadPluginApprovals(ctx, a.Conn)
	require.Error(t, err, "no view before version 5")
	signed := validLocal()
	signed.Signer = guardmodel.PluginSignerKnown
	requireCode(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, signed), guard.CodeLedgerInputInvalid)

	restore()
	d.NewAgent(t, "bot", leads, nil)
	require.Equal(t, guard.LatestVersion(), scalarOf[int](t, d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`))
	sql := guard.PluginApprovalsSQL(d.Names)
	for _, s := range []string{sql, sql, guard.StoreNeutralSQL(d.Names)} {
		d.Exec(t, "BEGIN; SET LOCAL ROLE "+d.Names.Guard()+"; SET LOCAL search_path = pg_catalog, pg_temp;"+s+"COMMIT;")
	}
	_, err = guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, signed))

	for fn, agents := range map[string]bool{
		"basalt_meta.open_plugin_approval(jsonb, jsonb)":                             true,
		"basalt_meta.submit_plugin_approval(uuid, bytea, bytea, bytea, bytea)":       true,
		"basalt_meta.record_plugin_event(text, jsonb)":                               true,
		"basalt_meta._check_plugin_approval_detail(jsonb)":                           false,
		"basalt_meta._check_plugin_approval_agents(jsonb)":                           false,
		"basalt_meta._plugin_approval_settings(jsonb, text)":                         false,
		"basalt_meta._plugin_approval_binding(uuid, timestamptz, name, jsonb, text)": false,
		"basalt_meta._plugin_approval_change(basalt_meta.plugin_approvals, jsonb)":   false,
		"basalt_meta._plugin_list_minus(jsonb, jsonb)":                               false,
		"basalt_meta._plugin_sorted(jsonb)":                                          false,
		"basalt_meta._check_plugin_detail(jsonb)":                                    false,
	} {
		require.False(t, scalarOf[bool](t, d.Admin, `SELECT has_function_privilege('public', $1, 'EXECUTE')`, fn), fn)
		require.Equal(t, agents, scalarOf[bool](t, d.Admin, `SELECT has_function_privilege($1, $2, 'EXECUTE')`, a.Role, fn), fn)
	}
	for table, sel := range map[string]bool{
		"basalt_meta.plugin_approvals": false, "basalt_meta.plugin_approval_ends": false, "basalt_meta.agent_plugin_approvals": true,
	} {
		require.Equal(t, sel, scalarOf[bool](t, d.Admin, `SELECT has_table_privilege($1, $2, 'SELECT')`, a.Role, table), table)
		require.False(t, scalarOf[bool](t, d.Admin, `SELECT has_table_privilege($1, $2, 'INSERT, UPDATE, DELETE')`, a.Role, table), table)
	}
}

// A plugin event may carry signer (version 5): UNKNOWN without a key id,
// KNOWN with one.
func TestPluginEventSigner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	unknown := validLocal()
	unknown.Signer, unknown.SignerKeyID = guardmodel.PluginSignerUnknown, ""
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, unknown))
	known := validLocal()
	known.Signer = guardmodel.PluginSignerKnown
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginChanged, known))
	recs, err := guard.ReadPluginRecords(ctx, a.Conn)
	require.NoError(t, err)
	require.Equal(t, []guardmodel.PluginDetail{known}, recs.EnabledPlugins())

	for name, mutate := range map[string]func(m map[string]any){
		"unknown with a key id":  func(m map[string]any) { m["signer"] = "UNKNOWN" },
		"known without a key id": func(m map[string]any) { m["signer"] = "KNOWN"; delete(m, "signerKeyId") },
		"no signer, no key id":   func(m map[string]any) { delete(m, "signerKeyId") },
		"another signer":         func(m map[string]any) { m["signer"] = "TRUSTED" },
		"signer not a string":    func(m map[string]any) { m["signer"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginEnabled), mutated(t, validLocal(), mutate)), guard.CodeLedgerInputInvalid)
		})
	}
	require.Equal(t, 2, pluginEvents(t, d, a.Role))
}

// The engine's recomputed settingsSha256 equals the one
// open_plugin_approval stored, byte for byte: config numbers as written
// (0.60 stays, 1e3 reads 1000), the two top-level numbers by value.
func TestPluginSettingsSHA256MatchesOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	mc := 0.6
	for _, s := range []guardmodel.PluginSettings{
		{},
		{Config: json.RawMessage(`{"threshold": 0.60, "max": 1e3, "z": [1.50, "x"], "a": {"b": null}}`), TimeoutMs: intPtr(300), MinConfidence: &mc},
		{MinConfidence: new(float64)},
	} {
		opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), s)
		require.NoError(t, err)
		rec, ok, err := guard.ReadPluginApproval(ctx, a.Conn, opened.ID)
		require.NoError(t, err)
		require.True(t, ok)
		got, err := guard.PluginSettingsSHA256(ctx, a.Conn, s)
		require.NoError(t, err)
		require.Equal(t, rec.Bound.SettingsSHA256, got, opened.SettingsText)
	}
}

// The settings hash cannot be steered by the agent's search_path: a type
// named text in a schema ahead of pg_catalog, with a cast from jsonb that
// always returns the approved text, is never used.
func TestPluginSettingsSHA256IgnoresSearchPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	d.Exec(t, `CREATE SCHEMA evil`)
	d.Exec(t, `GRANT USAGE ON SCHEMA evil TO PUBLIC`)
	d.Exec(t, `CREATE TYPE evil.text AS ENUM ('{}')`)
	d.Exec(t, `CREATE FUNCTION evil.f(pg_catalog.jsonb) RETURNS evil.text LANGUAGE sql IMMUTABLE AS $$ SELECT '{}'::evil.text $$`)
	d.Exec(t, `CREATE CAST (pg_catalog.jsonb AS evil.text) WITH FUNCTION evil.f(pg_catalog.jsonb)`)
	_, err := a.Conn.Exec(ctx, `SET search_path = evil, pg_catalog`)
	require.NoError(t, err)

	empty, err := guard.PluginSettingsSHA256(ctx, a.Conn, guardmodel.PluginSettings{})
	require.NoError(t, err)
	changed, err := guard.PluginSettingsSHA256(ctx, a.Conn, guardmodel.PluginSettings{Config: json.RawMessage(`{"dest": "https://x.example"}`)})
	require.NoError(t, err)
	require.NotEqual(t, empty, changed, "the hash is of the settings, whatever the search_path")
}
