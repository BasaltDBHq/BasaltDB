package setup

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// maxDatabaseName bounds a typed database name: Postgres names are at most
// 63 bytes.
const maxDatabaseName = 63

// WrongDatabaseName is the refusal of a removal whose typed name is not
// the database's.
const WrongDatabaseName = "Type the database's name exactly as the page shows it to remove BasaltDB from it. Nothing changed."

// RemovePlan is what removing BasaltDB from one database drops (CONTRACT.md,
// Setup jobs, Remove Basalt), read in the removal's transaction.
type RemovePlan struct {
	// Database is current_database().
	Database string
	// Prefix is the roles' prefix: the installed guard's, or the default
	// when no guard is installed.
	Prefix string
	// Installed: the database has basalt_meta.
	Installed bool
	// Agents are the agent names of the prefix's agent roles, sorted.
	Agents []string
	// demoSchema names the sample schema in Lines.
	demoSchema string
	// Drops are the guard's (guard.PlanUninstall); DemoDrops the sample
	// schema's, empty when the sample setup did not make it.
	Drops, DemoDrops []string
}

// Nothing reports a database with no guard, no agent role and no sample
// schema: a removal there only runs IF EXISTS drops.
func (p RemovePlan) Nothing() bool {
	return !p.Installed && len(p.Agents) == 0 && len(p.DemoDrops) == 0
}

// SQL is the plan's statements in the order they run: the guard's first,
// so a policy they drop on a sample table is still there to drop.
func (p RemovePlan) SQL() string {
	var b strings.Builder
	for _, sql := range append(slices.Clone(p.Drops), p.DemoDrops...) {
		b.WriteString(sql + ";\n")
	}
	return b.String()
}

// Lines are the plan's summary for the person, in fixed words and catalog
// names.
func (p RemovePlan) Lines() []string {
	var lines []string
	switch {
	case p.Nothing():
		lines = append(lines, fmt.Sprintf("BasaltDB is not in the database %s: there is nothing to drop.", p.Database))
	case !p.Installed:
		lines = append(lines, fmt.Sprintf("BasaltDB's schema basalt_meta is no longer in the database %s. This drops what is left: every %s_ role.", p.Database, p.Prefix))
	default:
		lines = append(lines, fmt.Sprintf("This removes BasaltDB from the database %s: the guard's row-level security policies, the schema basalt_meta with the ledger of every action, and every %s_ role. A view or other object of yours that uses the ledger is dropped with it (CASCADE).", p.Database, p.Prefix))
	}
	if len(p.Agents) > 0 {
		lines = append(lines, fmt.Sprintf("The bots that lose their access: %s. Nothing can undo this.", strings.Join(p.Agents, ", ")))
	}
	if len(p.DemoDrops) > 0 {
		lines = append(lines, "It drops the sample schema "+p.demoSchema+" with its rows, which the sample-database setup made. If another object depends on it, the schema stays.")
	}
	return lines
}

// PlanRemove reads the removal in q (the removal's transaction) and
// changes nothing. prefix is the roles' prefix when no guard is installed
// (guard.DefaultPrefix outside tests); a guard installed with another
// prefix is refused PREFIX_MISMATCH.
func PlanRemove(ctx context.Context, b SetuprunBackend, q Querier, prefix string) (RemovePlan, error) {
	database, err := b.CurrentDatabase(ctx, q)
	if err != nil {
		return RemovePlan{}, err
	}
	installed, err := b.InstalledPrefix(ctx, q)
	if err != nil {
		return RemovePlan{}, err
	}
	if installed != "" && installed != prefix {
		return RemovePlan{}, setuprunRefuse(string(setupcode.RefusalPrefixMismatch),
			fmt.Sprintf("This database's BasaltDB uses the prefix %s, not %s. Nothing changed.", installed, prefix))
	}
	names := guardmodel.Names{Prefix: prefix}
	roles, err := b.AgentRoles(ctx, q, names)
	if err != nil {
		return RemovePlan{}, err
	}
	agents := make([]string, 0, len(roles))
	for _, r := range roles {
		agents = append(agents, strings.TrimPrefix(r, prefix+"_agent_"))
	}
	slices.Sort(agents)
	drops, err := b.PlanUninstall(ctx, q, names)
	if err != nil {
		return RemovePlan{}, err
	}
	demoDrops, err := b.DemoPlanDrop(ctx, q)
	if err != nil {
		return RemovePlan{}, err
	}
	return RemovePlan{Database: database, Prefix: prefix, Installed: installed != "", Agents: agents, Drops: drops, DemoDrops: demoDrops, demoSchema: b.DemoSchema()}, nil
}

// InstalledRemovalPrefix is the role prefix a removal with no prefix of
// its own (the connect page's) uses: the installed guard's, read from the
// owner of basalt_meta, or def when no basalt_meta is installed. An owner
// that is not exactly <prefix>_guard with a valid prefix is refused
// PREFIX_MISMATCH: that schema is not BasaltDB's, and its owner's name must
// never pick the roles a removal drops.
func InstalledRemovalPrefix(ctx context.Context, b SetuprunBackend, q Querier, def string) (string, error) {
	owner, err := b.MetaOwner(ctx, q)
	if err != nil {
		return "", err
	}
	if owner == "" {
		return def, nil
	}
	prefix, ok := strings.CutSuffix(owner, "_guard")
	if !ok || (guardmodel.Names{Prefix: prefix}).Validate() != nil {
		return "", setuprunRefuse(string(setupcode.RefusalPrefixMismatch),
			"The schema basalt_meta in this database is not owned by a BasaltDB guard role, so it is not BasaltDB's. Nothing changed.")
	}
	return prefix, nil
}

// CheckDatabaseName refuses a typed name that cannot be a database's, before
// any connection is used.
func CheckDatabaseName(confirmName string) error {
	if confirmName == "" || len(confirmName) > maxDatabaseName {
		return setuprunRefuse(SetuprunCodeAnswersInvalid, WrongDatabaseName)
	}
	return nil
}

// CheckTypedName refuses, in the removal's transaction tx, a confirmName
// that is not current_database(): the first thing that transaction reads.
func CheckTypedName(ctx context.Context, b SetuprunBackend, tx Querier, confirmName string) error {
	if err := CheckDatabaseName(confirmName); err != nil {
		return err
	}
	database, err := b.CurrentDatabase(ctx, tx)
	if err != nil {
		return err
	}
	if confirmName != database {
		return setuprunRefuse(SetuprunCodeAnswersInvalid, WrongDatabaseName)
	}
	return nil
}

// RunRemove removes BasaltDB in tx: it refuses a confirmName that is not
// current_database() before it plans or drops anything, plans again and
// runs the drops. demoKept reports a sample schema another object depends
// on, which stays. A failed drop refuses SETUP_FAILED; the caller rolls
// tx back.
func RunRemove(ctx context.Context, b SetuprunBackend, tx Querier, prefix, confirmName string) (p RemovePlan, demoKept bool, err error) {
	if err := CheckTypedName(ctx, b, tx, confirmName); err != nil {
		return RemovePlan{}, false, err
	}
	if p, err = PlanRemove(ctx, b, tx, prefix); err != nil {
		return RemovePlan{}, false, err
	}
	for _, sql := range p.Drops {
		if err := b.Run(ctx, tx, sql); err != nil {
			return RemovePlan{}, false, &SetuprunRefusalError{
				Code:    SetuprunCodeSetupFailed,
				Message: "Removing BasaltDB failed, for example because one of its roles still has privileges in another database; nothing changed.", Err: err,
			}
		}
	}
	if demoKept, err = b.DemoApplyDrop(ctx, tx, p.DemoDrops); err != nil {
		return RemovePlan{}, false, err
	}
	return p, demoKept, nil
}
