package guard_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
)

const pinSHA = "807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa"

// The admin records a pin; the agent reads the latest one for its host and
// port and nothing for another; a newer record replaces the older.
func TestRecordTrustPin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()

	_, ok, err := guard.RecordedTrustPin(ctx, a.Conn, "db.example.com", 5432)
	require.NoError(t, err)
	require.False(t, ok)

	require.NoError(t, guard.RecordTrustPin(ctx, d.Admin, "db.example.com", 5432, pinSHA))
	sha, ok, err := guard.RecordedTrustPin(ctx, a.Conn, "db.example.com", 5432)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, pinSHA, sha)
	_, ok, err = guard.RecordedTrustPin(ctx, a.Conn, "db.example.com", 6543)
	require.NoError(t, err)
	require.False(t, ok, "another port has no pin")

	newer := "5f9b77951a7aa1303f9b58eea9bfa89e358cfdc15f9786ff10d4930a722c9ae2"
	require.NoError(t, guard.RecordTrustPin(ctx, d.Admin, "db.example.com", 5432, newer))
	sha, _, err = guard.RecordedTrustPin(ctx, a.Conn, "db.example.com", 5432)
	require.NoError(t, err)
	require.Equal(t, newer, sha)
	require.Equal(t, 2, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED'`))
	require.NoError(t, guard.RecordTrustPin(ctx, d.Admin, "203.0.113.7", 5432, pinSHA), "an address")
}

// An agent role cannot record a pin: it has no EXECUTE, and the function
// refuses agent roles itself.
func TestRecordTrustPinRefusesAgents(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	err := guard.RecordTrustPin(ctx, a.Conn, "db.example.com", 5432, pinSHA)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg), "%v", err)
	require.Equal(t, "42501", pg.Code, "no EXECUTE for agents")

	_, err = d.Admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION basalt_meta.record_trust_pin(text, int, text) TO `+a.Role)
	require.NoError(t, err)
	err = guard.RecordTrustPin(ctx, a.Conn, "db.example.com", 5432, pinSHA)
	requireCode(t, err, guard.CodeNotAllowed)
	require.Zero(t, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED'`))
}

// Bad input is refused.
func TestRecordTrustPinRefusesBadInput(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	for _, c := range map[string]struct {
		host string
		port int
		sha  string
	}{
		"empty host":     {"", 5432, pinSHA},
		"upper host":     {"DB.example.com", 5432, pinSHA},
		"quote in host":  {"db'.example.com", 5432, pinSHA},
		"port 0":         {"db.example.com", 0, pinSHA},
		"port too large": {"db.example.com", 65536, pinSHA},
		"short sha":      {"db.example.com", 5432, "abc"},
		"upper sha":      {"db.example.com", 5432, "807025AD50D4ED219D2C9C7D299C004F824EB00CF7F65AFEF607D07B72E6CAFA"},
	} {
		requireCode(t, guard.RecordTrustPin(ctx, d.Admin, c.host, c.port, c.sha), guard.CodeLedgerInputInvalid)
	}
}

// A guard below TrustPinsVersion has no agent_trust_pins: status reads no
// record and serves as before; the upgrade adds it. Not parallel: it
// limits the build's migrations.
func TestTrustPinsUpgrade(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, guard.TrustPinsVersion-1)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	_, ok, err := guard.RecordedTrustPin(ctx, a.Conn, "db.example.com", 5432)
	require.NoError(t, err, "no view is no record, not an error")
	require.False(t, ok)
	require.Error(t, guard.RecordTrustPin(ctx, d.Admin, "db.example.com", 5432, pinSHA))

	restore()
	d.NewAgent(t, "bot", leads, nil)
	require.NoError(t, guard.RecordTrustPin(ctx, d.Admin, "db.example.com", 5432, pinSHA))
	_, ok, err = guard.RecordedTrustPin(ctx, a.Conn, "db.example.com", 5432)
	require.NoError(t, err)
	require.True(t, ok)
}

// PUBLIC cannot run record_trust_pin.
func TestRecordTrustPinNotPublic(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, nil)
	var public bool
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT has_function_privilege('public', 'basalt_meta.record_trust_pin(text, int, text)', 'EXECUTE')`).Scan(&public))
	require.False(t, public)
}
