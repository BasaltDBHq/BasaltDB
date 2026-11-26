package setup

import (
	"context"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// Removing BasaltDB from a database (CONTRACT.md, Setup jobs, Remove Basalt)
// needs no setup code and no bot: only a connection the caller opened as
// the database's admin. Both steps use the installed guard's role prefix,
// or the default when no guard is installed.

// ContractRemoval is what removing BasaltDB from the connected database
// drops (pkg/setup's Removal).
type ContractRemoval struct {
	Database        string
	Bots            []string
	Lines           []string
	SQL             string
	NothingToRemove bool
	SampleSchema    bool
}

// ContractRemoved is a finished removal (pkg/setup's Removed).
type ContractRemoved struct {
	Database string
	Bots     []string
	Lines    []string
	Warnings []string
}

// CheckRemove reads, in a transaction it rolls back, what removing BasaltDB
// from conn's database drops, and changes nothing.
func (c Contract) CheckRemove(ctx context.Context, conn Querier) (ContractRemoval, error) {
	tx, err := c.be.BeginTx(ctx, conn)
	if err != nil {
		return ContractRemoval{}, err
	}
	defer func() { _ = c.be.RollbackTx(context.WithoutCancel(ctx), tx) }()
	prefix, err := c.removalPrefix(ctx, tx)
	if err != nil {
		return ContractRemoval{}, err
	}
	p, err := PlanRemove(ctx, c.be, tx, prefix)
	if err != nil {
		return ContractRemoval{}, err
	}
	return ContractRemoval{Database: p.Database, Bots: slices.Clone(p.Agents), Lines: p.Lines(), SQL: p.SQL(), NothingToRemove: p.Nothing(), SampleSchema: len(p.DemoDrops) > 0}, nil
}

// RunRemove removes BasaltDB from conn's database in one transaction:
// confirmName must equal current_database(), checked in that transaction
// before anything is planned or dropped. It plans again from the catalog.
func (c Contract) RunRemove(ctx context.Context, conn Querier, confirmName string) (ContractRemoved, error) {
	if err := CheckDatabaseName(confirmName); err != nil {
		return ContractRemoved{}, err
	}
	var out ContractRemoved
	err := c.be.BeginFunc(ctx, conn, func(tx Querier) error {
		// The typed name first: a wrong one learns nothing of the guard.
		if err := CheckTypedName(ctx, c.be, tx, confirmName); err != nil {
			return err
		}
		prefix, err := c.removalPrefix(ctx, tx)
		if err != nil {
			return err
		}
		p, kept, err := RunRemove(ctx, c.be, tx, prefix, confirmName)
		if err != nil {
			return err
		}
		out = ContractRemoved{Database: p.Database, Bots: slices.Clone(p.Agents), Warnings: []string{}}
		out.Lines = []string{"BasaltDB removed from the database " + p.Database}
		if len(p.Agents) > 0 {
			out.Lines = append(out.Lines, "bots that lost their access: "+strings.Join(p.Agents, ", "))
		}
		if kept {
			out.Warnings = append(out.Warnings, "the sample schema "+c.be.DemoSchema()+" stays: another object depends on it")
		}
		return nil
	})
	if err != nil {
		return ContractRemoved{}, err
	}
	return out, nil
}

// removalPrefix is the installed guard's prefix, or the default; a
// basalt_meta whose owner is not a guard role is refused PREFIX_MISMATCH.
func (c Contract) removalPrefix(ctx context.Context, tx Querier) (string, error) {
	return InstalledRemovalPrefix(ctx, c.be, tx, guardmodel.DefaultPrefix)
}
