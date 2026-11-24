package guard

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// Migrations lists every version this build installs, in order. Each one
// is breaking unless flagged non-breaking; flagging one needs a test that
// serves an agent on a guard without it (internal/app/servedagent,
// TestEveryNonBreakingMigrationIsServedWithoutIt).
func Migrations() []guardmodel.Migration {
	out := make([]guardmodel.Migration, 0, len(migrations))
	for _, m := range migrations {
		out = append(out, guardmodel.Migration{Version: m.version, Breaking: !m.nonBreaking})
	}
	return out
}

// AgentStatus reads the guard q (an agent connection) sees and compares it
// with migs. A missing version is one of migs not recorded in
// schema_version. Every version lets agents read schema_version, so an agent
// that cannot read it has no version this build knows: all are missing.
func AgentStatus(ctx context.Context, q Querier, migs []guardmodel.Migration) (guardmodel.Status, error) {
	st := guardmodel.Status{Build: buildVersion(migs)}
	var exists, readable bool
	// Plain SQL: catalog and privilege lookups, which any role may run.
	err := q.QueryRow(ctx, `SELECT to_regclass('basalt_meta.schema_version') IS NOT NULL,
		coalesce(has_table_privilege(to_regclass('basalt_meta.schema_version'), 'SELECT'), false)`).Scan(&exists, &readable)
	if err != nil {
		return guardmodel.Status{}, err
	}
	if !exists {
		st.State = guardmodel.GuardMissing
		return st, nil
	}
	installed, err := installedVersions(ctx, q, readable)
	if err != nil {
		return guardmodel.Status{}, err
	}
	return judge(installed, migs), nil
}

// StatusAt is the status of a guard whose newest installed version is
// installed (0: none), against migs. An install applies every version up to
// the newest one, so it counts versions 1 to installed as present: every
// version of migs after installed is missing. It judges a version read
// elsewhere (another build's engine) by this build's migrations, with the
// same rules as AgentStatus (judge).
func StatusAt(installed int, migs []guardmodel.Migration) guardmodel.Status {
	if installed == 0 {
		return guardmodel.Status{Build: buildVersion(migs), State: guardmodel.GuardMissing}
	}
	have := make([]int, installed)
	for i := range have {
		have[i] = i + 1
	}
	return judge(have, migs)
}

// judge is the one place a guard's recorded versions are compared with a
// build's migrations: AgentStatus and StatusAt both end here.
func judge(installed []int, migs []guardmodel.Migration) guardmodel.Status {
	st := guardmodel.Status{Build: buildVersion(migs)}
	for _, v := range installed {
		st.Installed = max(st.Installed, v)
	}
	for _, m := range migs {
		if slices.Contains(installed, m.Version) {
			continue
		}
		if m.Breaking {
			st.MissingBreaking = append(st.MissingBreaking, m.Version)
			continue
		}
		st.MissingNonBreaking = append(st.MissingNonBreaking, m.Version)
	}
	st.State = stateOf(st)
	return st
}

func stateOf(st guardmodel.Status) string {
	switch {
	case len(st.MissingBreaking) > 0:
		return guardmodel.GuardOutdated
	case len(st.MissingNonBreaking) > 0:
		return guardmodel.GuardUpgradeAvailable
	case st.Installed > st.Build:
		return guardmodel.GuardNewer
	}
	return guardmodel.GuardOK
}

// installedVersions are the versions recorded in schema_version, or none
// when the agent may not read it.
func installedVersions(ctx context.Context, q Querier, readable bool) ([]int, error) {
	if !readable {
		return nil, nil
	}
	sql, args, err := psql.Select("version").From("basalt_meta.schema_version").OrderBy("version").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int])
}

func buildVersion(migs []guardmodel.Migration) int {
	out := 0
	for _, m := range migs {
		out = max(out, m.Version)
	}
	return out
}
