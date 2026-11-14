package guard_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

func engineKey(t *testing.T) []byte {
	t.Helper()
	k, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	return k.PublicKeySPKI()
}

func ptr[T any](v T) *T { return &v }

func requireEngineRefused(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Equal(t, detail, pg.Detail)
}

// The person's computer records an engine's key with its address; Postgres
// computes the id, the agent reads the row, and the ledger has it.
func TestRecordEngine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)

	id, err := guard.RecordEngine(ctx, d.Admin, key, ptr("https://engine.example.com"))
	require.NoError(t, err)
	require.Equal(t, channel.EngineIDOf(key), id, "the id is computed from the key")

	// Recording it again unchanged writes nothing; a nil address keeps it.
	again, err := guard.RecordEngine(ctx, d.Admin, key, ptr("https://engine.example.com"))
	require.NoError(t, err)
	require.Equal(t, id, again)
	_, err = guard.RecordEngine(ctx, d.Admin, key, nil)
	require.NoError(t, err)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'ENGINE_RECORDED'`))

	// A new address replaces the old one, with a ledger row naming both.
	_, err = guard.RecordEngine(ctx, d.Admin, key, ptr("https://tunnel.example.org:8443"))
	require.NoError(t, err)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'ENGINE_RECORDED'
		AND detail ->> 'engineId' = $1 AND detail ->> 'url' = 'https://tunnel.example.org:8443'
		AND detail ->> 'previousUrl' = 'https://engine.example.com' AND detail ->> 'by' = session_user`, id))

	engines, err := guard.Engines(ctx, a.Conn, false)
	require.NoError(t, err)
	require.Len(t, engines, 1)
	require.Equal(t, id, engines[0].ID)
	require.True(t, bytes.Equal(key, engines[0].PublicKey))
	require.Equal(t, "https://tunnel.example.org:8443", *engines[0].URL)
	require.Nil(t, engines[0].RevokedAt)
	require.Nil(t, scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`))

	// A key recorded with no address has none.
	other, err := guard.RecordEngine(ctx, d.Admin, engineKey(t), nil)
	require.NoError(t, err)
	require.Nil(t, scalarOf[*string](t, d.Admin, `SELECT url FROM basalt_meta.engines WHERE engine_id = $1`, other))
}

func TestRecordEngineRefusesABadKey(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)

	offCurve := bytes.Clone(key)
	offCurve[len(offCurve)-1] ^= 1
	compressed := append(bytes.Clone(key[:26]), 0x02)
	compressed = append(compressed, key[27:59]...)
	wrongCurve := bytes.Clone(key)
	wrongCurve[20] ^= 1 // inside the curve OID

	for name, k := range map[string][]byte{
		"empty": {}, "short": key[:90], "long": append(bytes.Clone(key), 0),
		"off the curve": offCurve, "compressed": compressed, "another curve": wrongCurve,
	} {
		_, err := guard.RecordEngine(ctx, d.Admin, k, nil)
		requireEngineRefused(t, err, guard.EngineRefusedKey)
		t.Log(name, "refused")
	}
	_, err := guard.RecordEngine(ctx, d.Admin, nil, nil)
	requireEngineRefused(t, err, guard.EngineRefusedKey)
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(engine_id)::int FROM basalt_meta.engines`))
}

func TestRecordEngineRefusesABadAddress(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)

	for _, u := range []string{
		"", "http://engine.example.com", "https://engine.example.com/", "https://engine.example.com/path",
		"https://engine.example.com?q=1", "https://engine.example.com#f", "https://user@engine.example.com",
		"https://Engine.example.com", "https://engine.example.com.", "https://engine", "https://1.2.3.4",
		"https://[::1]", "https://localhost", "https://a.localhost", "https://basaltvault.app",
		"https://portal.basaltvault.app", "https://engine.example.com:443", "https://engine.example.com:0",
		"https://engine.example.com:65536", "https://engine.example.com:08443", "https://-bad.example.com",
		"https://engine.example.com:", " https://engine.example.com", "wss://engine.example.com",
		"https://localhost.", "https://portal.basaltvault.app.", "https://0x7f.1",
		"https://127.1", "https://2130706433", "https://printer.local", "https://db.internal", "https://nas.home.arpa",
		"https://engine.localhost", "https://b%C3%BCcher.example", "https://bücher.example", "https://engine.example.123",
	} {
		_, err := guard.RecordEngine(ctx, d.Admin, key, &u)
		requireEngineRefused(t, err, guard.EngineRefusedURL)
		t.Log(u, "refused")
	}
	for _, u := range []string{
		"https://engine.example.com", "https://xn--bcher-kva.example", "https://a-b.c-d.example:8443",
		"https://my-engine.tail1234.ts.net", "https://notbasaltvault.app", "https://engine.example.com:65535",
		"https://1.2.3.example", "https://engine.example.com:1",
	} {
		_, err := guard.RecordEngine(ctx, d.Admin, key, &u)
		require.NoError(t, err, u)
	}
}

// A revoked engine stays revoked: its id is never recorded again, and a
// second revocation is refused as an unknown id.
func TestRevokeEngine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)
	id, err := guard.RecordEngine(ctx, d.Admin, key, ptr("https://engine.example.com"))
	require.NoError(t, err)
	_, err = guard.RecordEngine(ctx, d.Admin, engineKey(t), nil)
	require.NoError(t, err)

	remaining, err := guard.RevokeEngine(ctx, d.Admin, id)
	require.NoError(t, err)
	require.Equal(t, 1, remaining)

	engines, err := guard.Engines(ctx, a.Conn, false)
	require.NoError(t, err)
	require.Len(t, engines, 2, "the agent sees revoked engines too, with when")
	for _, e := range engines {
		require.Equal(t, e.ID == id, e.RevokedAt != nil)
	}

	_, err = guard.RecordEngine(ctx, d.Admin, key, nil)
	requireEngineRefused(t, err, guard.EngineRefusedRevoked)
	_, err = guard.RecordEngine(ctx, d.Admin, key, ptr("https://elsewhere.example.com"))
	requireEngineRefused(t, err, guard.EngineRefusedRevoked)
	_, err = guard.RevokeEngine(ctx, d.Admin, id)
	requireEngineRefused(t, err, guard.EngineRefusedUnknown)
	_, err = guard.RevokeEngine(ctx, d.Admin, "AAAAAAAAAAAAAAAAAAAAAA")
	requireEngineRefused(t, err, guard.EngineRefusedUnknown)

	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'ENGINE_REVOKED'
		AND detail ->> 'engineId' = $1 AND detail ->> 'url' = 'https://engine.example.com'
		AND (detail ->> 'remaining')::int = 1 AND detail ->> 'by' = session_user`, id))
	require.Equal(t, "https://engine.example.com", scalarOf[string](t, d.Admin,
		`SELECT url FROM basalt_meta.engines WHERE engine_id = $1`, id), "a refused re-record changes nothing")
	require.Nil(t, scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`))
}

// The agent role can neither record nor revoke an engine, nor write the
// table: the bot cannot pin an address or undo a revocation.
func TestAgentCannotRecordOrRevokeAnEngine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)
	id, err := guard.RecordEngine(ctx, d.Admin, key, ptr("https://engine.example.com"))
	require.NoError(t, err)

	requireDenied := func(err error) {
		t.Helper()
		var pg *pgconn.PgError
		require.True(t, errors.As(err, &pg), "%v", err)
		require.Equal(t, "42501", pg.Code, pg.Message)
	}
	_, err = guard.RecordEngine(ctx, a.Conn, engineKey(t), ptr("https://bot.example.com"))
	requireDenied(err)
	_, err = guard.RevokeEngine(ctx, a.Conn, id)
	requireDenied(err)
	_, err = a.Conn.Exec(ctx, `UPDATE basalt_meta.engines SET url = 'https://bot.example.com'`)
	requireDenied(err)
	_, err = a.Conn.Exec(ctx, `UPDATE basalt_meta.agent_engines SET url = 'https://bot.example.com'`)
	requireDenied(err)
	_, err = guard.Engines(ctx, a.Conn, true)
	requireDenied(err)

	require.Equal(t, "https://engine.example.com", scalarOf[string](t, d.Admin,
		`SELECT url FROM basalt_meta.engines WHERE engine_id = $1`, id))
	require.Nil(t, scalarOf[*time.Time](t, d.Admin, `SELECT revoked_at FROM basalt_meta.engines WHERE engine_id = $1`, id))
}
