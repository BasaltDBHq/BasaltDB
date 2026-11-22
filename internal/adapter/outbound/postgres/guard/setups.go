package guard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// RecordSetup records s with the admin connection, in the transaction that
// applies the code, and returns the seq of its AGENT_SETUP ledger row. Kept
// for tests, which run record_setup through it and read the seq back; the
// setup shows RecordSetupStatement, the SQL the person reads.
// Postgres refuses a used, superseded, expired or forged-time code with
// SETUP_REFUSED (see SetupRefusal).
func RecordSetup(ctx context.Context, q Querier, n Names, s Setup) (int64, error) {
	if err := n.Validate(); err != nil {
		return 0, err
	}
	var agent any // NULL for UPGRADE
	if s.Agent != "" {
		role, err := n.Agent(s.Agent)
		if err != nil {
			return 0, err
		}
		agent = role
	}
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.record_setup(?::uuid, ?::text, ?::name, ?::int, ?::timestamptz)",
		s.ID, s.Kind, agent, s.GuardVersion, s.ExpiresAt)).ToSql()
	if err != nil {
		return 0, err
	}
	var seq int64
	err = q.QueryRow(ctx, sql, args...).Scan(&seq)
	return seq, err
}

// RecordSetupStatement is record_setup as one statement with its values
// written in, so the SQL a person reads before saying yes shows it. Every
// value is checked or formatted here: a UUID, a kind of three, a role from
// Names, an int and a UTC time.
func RecordSetupStatement(n Names, s Setup) (Statement, error) {
	if err := n.Validate(); err != nil {
		return Statement{}, err
	}
	switch s.Kind {
	case SetupInstall, SetupAgent, SetupUpgrade:
	default:
		return Statement{}, fmt.Errorf("%w: setup kind %q", ErrInvalidAgent, s.Kind)
	}
	agent := "NULL"
	if s.Agent != "" {
		role, err := n.Agent(s.Agent)
		if err != nil {
			return Statement{}, err
		}
		agent = quoteLiteral(role)
	}
	sql := fmt.Sprintf("\nSELECT basalt_meta.record_setup(%s::uuid, %s, %s::name, %d, %s::timestamptz);",
		quoteLiteral(s.ID.String()), quoteLiteral(s.Kind), agent, s.GuardVersion,
		quoteLiteral(s.ExpiresAt.UTC().Format(time.RFC3339)))
	return Statement{SQL: sql}, nil
}

// SetupRefusal returns the reason (SetupUsed, ...) of a SETUP_REFUSED
// error, and false when err is not one.
func SetupRefusal(err error) (string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != sqlstateSetupRefused {
		return "", false
	}
	return pg.Detail, true
}

// CheckVerifier returns ErrInvalidAgent unless v is a SCRAM-SHA-256
// verifier in the setup code's format, with canonical base64. Its alphabet
// holds no quote or backslash.
func CheckVerifier(v string) error {
	if !setupcode.ValidVerifier(v) {
		return fmt.Errorf("%w: the password must be a SCRAM-SHA-256 verifier", ErrInvalidAgent)
	}
	return nil
}

// SetupRecorded reports whether setup id is recorded, read with the agent's
// own connection through basalt_meta.agent_setups (an agent sees its own
// setups and every UPGRADE). A guard older than version 16 has no setups:
// false.
func SetupRecorded(ctx context.Context, q Querier, id uuid.UUID) (bool, error) {
	var readable bool
	// Plain SQL: catalog and privilege lookups, which any role may run.
	err := q.QueryRow(ctx, `SELECT coalesce(has_table_privilege(to_regclass('basalt_meta.agent_setups'), 'SELECT'), false)`).Scan(&readable)
	if err != nil || !readable {
		return false, err
	}
	sql, args, err := psql.Select("1").From("basalt_meta.agent_setups").Where(sq.Eq{"setup_id": id}).Prefix("SELECT EXISTS (").Suffix(")").ToSql()
	if err != nil {
		return false, err
	}
	var found bool
	err = q.QueryRow(ctx, sql, args...).Scan(&found)
	return found, err
}

// LatestAgentSetup is the newest setup the agent connection q sees through
// basalt_meta.agent_setups: its own setups and every UPGRADE. ok is false
// when none is recorded or the guard has no setups (before version 16).
func LatestAgentSetup(ctx context.Context, q Querier) (s AgentSetup, ok bool, err error) {
	var readable bool
	// Plain SQL: catalog and privilege lookups, which any role may run.
	err = q.QueryRow(ctx, `SELECT coalesce(has_table_privilege(to_regclass('basalt_meta.agent_setups'), 'SELECT'), false)`).Scan(&readable)
	if err != nil || !readable {
		return AgentSetup{}, false, err
	}
	sql, args, err := psql.Select("setup_id", "kind").From("basalt_meta.agent_setups").
		OrderBy("used_at DESC", "setup_id DESC").Limit(1).ToSql()
	if err != nil {
		return AgentSetup{}, false, err
	}
	err = q.QueryRow(ctx, sql, args...).Scan(&s.SetupID, &s.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentSetup{}, false, nil
	}
	if err != nil {
		return AgentSetup{}, false, err
	}
	return s, true, nil
}

// InstalledPrefix is the prefix of the installed basalt_meta, read from
// the owner of the schema (<prefix>_guard); "" when none is installed. An
// owner that is not a guard role is returned whole, so it never matches a
// code's prefix.
func InstalledPrefix(ctx context.Context, q Querier) (string, error) {
	var owner string
	err := q.QueryRow(ctx, `SELECT coalesce((SELECT pg_catalog.pg_get_userbyid(n.nspowner)::text
		FROM pg_catalog.pg_namespace n WHERE n.nspname = 'basalt_meta'), '')`).Scan(&owner)
	if err != nil {
		return "", err
	}
	if prefix, ok := strings.CutSuffix(owner, guardSuffix); ok && prefix != "" {
		return prefix, nil
	}
	return owner, nil
}

// guardSuffix ends the name of the role that owns basalt_meta.
const guardSuffix = "_guard"

// SetupsFor lists the recorded setups a code is checked against: the
// code's own setup id and every setup of role ("" for none). Nothing
// before version 16, which has no setups table.
func SetupsFor(ctx context.Context, q Querier, id uuid.UUID, role string) ([]setupcode.RecordedSetup, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('basalt_meta.setups') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return nil, err
	}
	where := sq.Or{sq.Eq{"setup_id": id}}
	if role != "" {
		where = append(where, sq.Eq{"agent_role": role})
	}
	sql, args, err := psql.Select("setup_id::text", "coalesce(agent_role::text, '')", "used_at").
		From("basalt_meta.setups").Where(where).OrderBy("setup_id").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (setupcode.RecordedSetup, error) {
		var s setupcode.RecordedSetup
		err := row.Scan(&s.SetupID, &s.AgentRole, &s.UsedAt)
		return s, err
	})
}

// RoleTimeouts is the statement_timeout a role has set, as Postgres stores
// it ("30000", "30s"); "" for one it has not set.
type RoleTimeouts struct {
	// AllDatabases is ALTER ROLE ... SET, what basalt sets.
	AllDatabases string
	// ThisDatabase is ALTER ROLE ... IN DATABASE <the connected one> SET,
	// which takes precedence over AllDatabases in that database.
	ThisDatabase string
}

// RoleStatementTimeout is the statement_timeout role has set for every
// database and for the connected database only.
func RoleStatementTimeout(ctx context.Context, q Querier, role string) (RoleTimeouts, error) {
	var v RoleTimeouts
	// Raw SQL: a catalog query over unnest(setconfig) with FILTER aggregates.
	err := q.QueryRow(ctx, `SELECT
		coalesce(max(substr(c, length('statement_timeout=') + 1)) FILTER (WHERE s.setdatabase = 0), ''),
		coalesce(max(substr(c, length('statement_timeout=') + 1)) FILTER (WHERE s.setdatabase <> 0), '')
		FROM pg_catalog.pg_db_role_setting s
		JOIN pg_catalog.pg_roles r ON r.oid = s.setrole, LATERAL unnest(s.setconfig) c
		WHERE r.rolname = $1 AND c LIKE 'statement\_timeout=%'
		AND s.setdatabase IN (0, (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database()))`, role).
		Scan(&v.AllDatabases, &v.ThisDatabase)
	return v, err
}
