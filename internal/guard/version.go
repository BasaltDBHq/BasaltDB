package guard

import (
	"context"
	"fmt"
)

// StaleSchemaError is an installed basalt_meta older than this build's.
type StaleSchemaError struct {
	// Installed is the installed version. When the agent cannot read
	// schema_version (a guard from before versionAgentVersion), it is the
	// version before that one and Unreadable is set.
	Installed  int
	Unreadable bool
	Latest     int
}

func (e *StaleSchemaError) Error() string {
	installed := fmt.Sprintf("v%d", e.Installed)
	if e.Unreadable {
		installed += " or earlier"
	}
	return fmt.Sprintf("guard schema %s is older than this build's v%d: run basalt init again to upgrade it (same flags as before)",
		installed, e.Latest)
}

// CheckAgentVersion returns a *StaleSchemaError when the basalt_meta that q
// (an agent connection) sees is older than LatestVersion. A database
// without basalt_meta reports version 0.
func CheckAgentVersion(ctx context.Context, q Querier) error {
	var exists, readable bool
	// Plain SQL: catalog and privilege lookups, which any role may run.
	err := q.QueryRow(ctx, `SELECT to_regclass('basalt_meta.schema_version') IS NOT NULL,
		coalesce(has_table_privilege(to_regclass('basalt_meta.schema_version'), 'SELECT'), false)`).Scan(&exists, &readable)
	if err != nil {
		return err
	}
	latest := LatestVersion()
	if !exists {
		return &StaleSchemaError{Installed: 0, Latest: latest}
	}
	if !readable {
		return &StaleSchemaError{Installed: versionAgentVersion - 1, Unreadable: true, Latest: latest}
	}
	installed, err := InstalledVersion(ctx, q)
	if err != nil {
		return err
	}
	if installed >= latest {
		return nil
	}
	return &StaleSchemaError{Installed: installed, Latest: latest}
}
