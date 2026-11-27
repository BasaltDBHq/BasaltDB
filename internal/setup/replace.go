package setup

import (
	"context"
	"fmt"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// Replacing an install below the update floor (CONTRACT.md, The local
// setup page, An older install): no update reaches such a guard, so the
// install removes it and installs again, in one transaction. Its check
// removes it too, in a transaction it rolls back, so what it shows is
// planned on the database as the run will find it. The person confirms the
// removal by typing the database's name, as for Remove BasaltDB. The
// sample schema and the person's own tables and rows stay.

// ReplaceWrongName is the refusal of a replace whose typed name is not
// the database's.
const ReplaceWrongName = "Type the database's name exactly as the page shows it to remove the old BasaltDB install and set up. Nothing changed."

// ReplaceNotNeeded is the refusal of a typed name on an install that
// replaces nothing.
const ReplaceNotNeeded = "This database has no BasaltDB install too old to update, so the setup takes no database name. Check the setup again. Nothing changed."

// Replace is what a check found about a guard below the update floor,
// for the person's first screen: the old install's guard version and
// recorded release, and this build's.
type Replace struct {
	// GuardVersion is the old install's guard version; Floor the lowest
	// version this build updates in place.
	GuardVersion int `json:"guardVersion"`
	Floor        int `json:"floor"`
	// Release is the BasaltDB release recorded with GuardVersion, "" when
	// the guard records none.
	Release string `json:"release,omitempty"`
	// This is this build's release.
	This string `json:"this"`
	// Lines are the first screen's words, built from the fields above.
	Lines []string `json:"lines"`
}

// ThisRelease is this build's release, as schema_version records it.
func ThisRelease() string { return strings.TrimPrefix(buildinfo.Version, "v") }

// ReplaceOf is the check's account of old.
func ReplaceOf(old guardmodel.OldInstall) *Replace {
	r := &Replace{GuardVersion: old.Version, Floor: old.Floor, Release: old.Release, This: ThisRelease()}
	r.Lines = ReplaceLines(*r)
	return r
}

// ReplaceLines are the first screen's words for r, from its fields only:
// never a fixed release name.
func ReplaceLines(r Replace) []string {
	set := fmt.Sprintf("It has guard version %d.", r.GuardVersion)
	if r.Release != "" {
		set = fmt.Sprintf("It was set up by BasaltDB %s (guard version %d).", r.Release, r.GuardVersion)
	}
	return []string{
		"This BasaltDB install is too old to update.",
		set,
		fmt.Sprintf("BasaltDB %s needs guard version %d or later.", r.This, r.Floor),
		"Setting up removes the old install first: its agents' history and undo, their held approvals and the passkeys go with it. Your tables and rows stay.",
	}
}

// ReadReplace reads, in q, whether the guard is below the update floor: nil
// when it is not.
func ReadReplace(ctx context.Context, b SetuprunBackend, q Querier) (*guardmodel.OldInstall, error) {
	old, ok, err := b.ReadOldInstall(ctx, q)
	if err != nil || !ok {
		return nil, err
	}
	return &old, nil
}

// RemoveOld runs, in tx, the removal of the guard of n below the update
// floor, as Remove BasaltDB plans it from the catalog (PlanUninstall: the
// policies named after its roles, basalt_meta, the agent roles, the group
// and the guard role), and returns the statements it ran. The sample
// schema stays. A failed drop refuses SETUP_FAILED; the caller rolls tx
// back.
func RemoveOld(ctx context.Context, b SetuprunBackend, tx Querier, n guardmodel.Names) ([]string, error) {
	drops, err := b.PlanUninstall(ctx, tx, n)
	if err != nil {
		return nil, err
	}
	for _, sql := range drops {
		if err := b.Run(ctx, tx, sql); err != nil {
			return nil, &SetuprunRefusalError{
				Code:    SetuprunCodeSetupFailed,
				Message: "Removing the old BasaltDB install failed, for example because one of its roles still has privileges in another database; nothing changed.", Err: err,
			}
		}
	}
	return drops, nil
}

// RemovedSQL is the removal's statements as the setup's SQL shows them,
// before the install's.
func RemovedSQL(drops []string) string {
	var b strings.Builder
	for _, sql := range drops {
		b.WriteString(sql + ";\n")
	}
	return b.String()
}
