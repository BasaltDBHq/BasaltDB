package guard_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

func engineKey(t *testing.T) []byte {
	t.Helper()
	k, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	return k.PublicKeySPKI()
}

func requireEngineRefused(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Equal(t, detail, pg.Detail)
}

// The person's computer records an engine's key; Postgres computes the id,
// the agent reads the row, and the ledger has it.
func TestRecordEngine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)

	id, err := guard.RecordEngine(ctx, d.Admin, key)
	require.NoError(t, err)
	require.Equal(t, channel.EngineIDOf(key), id, "the id is computed from the key")

	// Recording it again writes nothing.
	again, err := guard.RecordEngine(ctx, d.Admin, key)
	require.NoError(t, err)
	require.Equal(t, id, again)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'ENGINE_RECORDED'
		AND detail ->> 'engineId' = $1 AND detail ->> 'by' = session_user AND NOT detail ? 'url'`, id))

	engines, err := guard.Engines(ctx, a.Conn, false)
	require.NoError(t, err)
	require.Len(t, engines, 1)
	require.Equal(t, id, engines[0].ID)
	require.True(t, bytes.Equal(key, engines[0].PublicKey))
	require.Nil(t, engines[0].RevokedAt)
	require.Nil(t, scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`))

	// The engine address is gone: no column, no two-argument function.
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(attname)::int FROM pg_catalog.pg_attribute
		WHERE attrelid = 'basalt_meta.engines'::regclass AND attname = 'url' AND NOT attisdropped`))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(oid)::int FROM pg_catalog.pg_proc
		WHERE proname = 'record_engine' AND pronamespace = 'basalt_meta'::regnamespace`))
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(oid)::int FROM pg_catalog.pg_proc
		WHERE proname = '_engine_url_ok' AND pronamespace = 'basalt_meta'::regnamespace`))
	var public bool
	require.NoError(t, d.Admin.QueryRow(ctx,
		`SELECT has_function_privilege('public', 'basalt_meta.record_engine(bytea)', 'EXECUTE')`).Scan(&public))
	require.False(t, public, "PUBLIC cannot run it")
	var agentCan bool
	require.NoError(t, d.Admin.QueryRow(ctx,
		`SELECT has_function_privilege($1, 'basalt_meta.record_engine(bytea)', 'EXECUTE')`, a.Role).Scan(&agentCan))
	require.False(t, agentCan, "the agent role cannot run it")
}

// A guard installed up to version 7 records an engine with its address; the
// upgrade drops the address and keeps the record, its revocation and the
// chain. The engine's reads work on both.
func TestEngineAddressRemovedUpgrade(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, guard.EngineAddressRemovedVersion-1)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	key, revoked := engineKey(t), engineKey(t)
	for _, k := range [][]byte{key, revoked} {
		_, err := d.Admin.Exec(ctx, guard.RecordEngineStatement(k, guard.EngineAddressRemovedVersion-1).SQL)
		require.NoError(t, err)
	}
	_, err := d.Admin.Exec(ctx, `UPDATE basalt_meta.engines SET url = 'https://engine.example.com' WHERE engine_id = $1`, channel.EngineIDOf(key))
	require.NoError(t, err)
	_, err = guard.RevokeEngine(ctx, d.Admin, channel.EngineIDOf(revoked))
	require.NoError(t, err)
	rec, err := guard.EngineRecord(ctx, a.Conn, channel.EngineIDOf(key))
	require.NoError(t, err, "the engine reads its record on a guard without version 8")
	require.NotNil(t, rec)

	restore()
	d.NewAgent(t, "bot", leads, leads)
	require.Equal(t, guard.LatestVersion(), scalarOf[int](t, d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`))
	engines, err := guard.Engines(ctx, a.Conn, false)
	require.NoError(t, err)
	require.Len(t, engines, 2)
	for _, e := range engines {
		require.Equal(t, e.ID == channel.EngineIDOf(revoked), e.RevokedAt != nil)
	}
	_, err = guard.RecordEngine(ctx, d.Admin, revoked)
	requireEngineRefused(t, err, guard.EngineRefusedRevoked)
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(oid)::int FROM pg_catalog.pg_proc
		WHERE proname = 'record_engine' AND pronamespace = 'basalt_meta'::regnamespace AND pronargs = 2`))
	require.Nil(t, scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`))
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
		_, err := guard.RecordEngine(ctx, d.Admin, k)
		requireEngineRefused(t, err, guard.EngineRefusedKey)
		t.Log(name, "refused")
	}
	_, err := guard.RecordEngine(ctx, d.Admin, nil)
	requireEngineRefused(t, err, guard.EngineRefusedKey)
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(engine_id)::int FROM basalt_meta.engines`))
}

// A revoked engine stays revoked: its id is never recorded again, and a
// second revocation is refused as an unknown id.
func TestRevokeEngine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)
	id, err := guard.RecordEngine(ctx, d.Admin, key)
	require.NoError(t, err)
	_, err = guard.RecordEngine(ctx, d.Admin, engineKey(t))
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

	_, err = guard.RecordEngine(ctx, d.Admin, key)
	requireEngineRefused(t, err, guard.EngineRefusedRevoked)
	_, err = guard.RevokeEngine(ctx, d.Admin, id)
	requireEngineRefused(t, err, guard.EngineRefusedUnknown)
	_, err = guard.RevokeEngine(ctx, d.Admin, "AAAAAAAAAAAAAAAAAAAAAA")
	requireEngineRefused(t, err, guard.EngineRefusedUnknown)

	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'ENGINE_REVOKED'
		AND detail ->> 'engineId' = $1 AND NOT detail ? 'url'
		AND (detail ->> 'remaining')::int = 1 AND detail ->> 'by' = session_user`, id))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'ENGINE_RECORDED'
		AND detail ->> 'engineId' = $1`, id), "a refused re-record writes nothing")
	require.Nil(t, scalarOf[*int64](t, d.Admin, `SELECT basalt_meta.verify_chain()`))
}

// The agent role can neither record nor revoke an engine, nor write the
// table: the bot cannot record its own key or undo a revocation.
func TestAgentCannotRecordOrRevokeAnEngine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	key := engineKey(t)
	id, err := guard.RecordEngine(ctx, d.Admin, key)
	require.NoError(t, err)
	_, err = guard.RevokeEngine(ctx, d.Admin, id)
	require.NoError(t, err)

	requireDenied := func(err error) {
		t.Helper()
		var pg *pgconn.PgError
		require.True(t, errors.As(err, &pg), "%v", err)
		require.Equal(t, "42501", pg.Code, pg.Message)
	}
	_, err = guard.RecordEngine(ctx, a.Conn, engineKey(t))
	requireDenied(err)
	_, err = guard.RevokeEngine(ctx, a.Conn, id)
	requireDenied(err)
	_, err = a.Conn.Exec(ctx, `UPDATE basalt_meta.engines SET revoked_at = NULL, revoked_by = NULL`)
	requireDenied(err)
	_, err = a.Conn.Exec(ctx, `UPDATE basalt_meta.agent_engines SET revoked_at = NULL`)
	requireDenied(err)
	_, err = guard.Engines(ctx, a.Conn, true)
	requireDenied(err)

	require.NotNil(t, scalarOf[*time.Time](t, d.Admin, `SELECT revoked_at FROM basalt_meta.engines WHERE engine_id = $1`, id))
}
