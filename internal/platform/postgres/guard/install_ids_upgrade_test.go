package guard_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// legacyInstall is the uuid agent_reinstalls shows for a report recorded
// before install ids: zeros, then the oid in the last 12 hex digits.
func legacyInstall(t *testing.T, oid uint32) uuid.UUID {
	t.Helper()
	return uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012x", oid))
}

// A guard installed at version 1, as the first releases did, identifies its
// install by the schema oid. Upgrading it to install ids keeps its install
// record, gives it a random id, keeps the reinstall reports already in the
// ledger readable under their oids, and takes reports by install id.
func TestUpgradeToInstallIDs(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, 1)
	d := guardtest.New(t).WithDemo(t)
	bot := d.NewAgent(t, "bot", leads, nil)

	var schemaOID uint32
	var installedAt time.Time
	// Plain SQL: fixture reads of the version 1 tables.
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT i.install::bigint, i.installed_at
		FROM basalt_meta.installs i JOIN pg_catalog.pg_namespace n ON n.oid = i.install
		WHERE n.nspname = 'basalt_meta'`).Scan(&schemaOID, &installedAt))
	const pinnedOID = 12345
	hash := bytes.Repeat([]byte{7}, 32)
	var recorded bool
	require.NoError(t, bot.Conn.QueryRow(ctx, `SELECT basalt_meta.record_pin_set_aside(0, $1, $2::oid)`,
		hash, pinnedOID).Scan(&recorded))
	require.True(t, recorded)

	restore()
	d.NewAgent(t, "bot", leads, nil)

	require.Equal(t, 1, count(t, d.Admin, `SELECT count(install)::int FROM basalt_meta.installs`))
	install, err := guard.InstallID(ctx, bot.Conn)
	require.NoError(t, err, "an agent reads the install id")
	require.NotEqual(t, uuid.Nil, install)
	row, ok := readInstall(t, d, install)
	require.True(t, ok)
	require.True(t, installedAt.Equal(row.At), "the upgrade keeps the install's time")
	require.Equal(t, adminUser(t, d), row.By)

	var pinned, at uuid.UUID
	require.NoError(t, bot.Conn.QueryRow(ctx, `SELECT pinned_install, install FROM basalt_meta.agent_reinstalls`).
		Scan(&pinned, &at))
	require.Equal(t, legacyInstall(t, pinnedOID), pinned)
	require.Equal(t, legacyInstall(t, schemaOID), at)

	other := uuid.New()
	ok, err = guard.RecordPinSetAside(ctx, bot.Conn, guard.ChainHead{Seq: 0, Hash: hash}, other)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2, count(t, d.Admin, `SELECT count(at)::int FROM basalt_meta.agent_reinstalls`))
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(oid)::int FROM pg_catalog.pg_proc
		WHERE proname = 'record_pin_set_aside' AND pg_catalog.pg_get_function_identity_arguments(oid) LIKE '%oid%'`),
		"the oid form is gone")
}
