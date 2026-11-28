package setup

import (
	"context"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
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

// RunRemove removes BasaltDB from conn's database in one transaction. The
// admin login is the confirmation: there is no typed name. It plans again
// from the catalog.
func (c Contract) RunRemove(ctx context.Context, conn Querier) (ContractRemoved, error) {
	var out ContractRemoved
	err := c.be.BeginFunc(ctx, conn, func(tx Querier) error {
		prefix, err := c.removalPrefix(ctx, tx)
		if err != nil {
			return err
		}
		p, kept, err := RunRemove(ctx, c.be, tx, prefix, "")
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

// RunRemoveCode is RunRemove for a removal link's code (basalt init
// --remove on an agent-operated engine; CONTRACT.md, Connect, The removal
// hand-off): before anything is planned or dropped, the code must decode
// and be live, carry a target and an engine key, and conn must be the
// code's target (TARGET_MISMATCH). The hold the caller keeps afterwards is
// for the code's setupId and engine key only.
func (c Contract) RunRemoveCode(ctx context.Context, conn Querier, at ConnConfig, req ContractRequest) (ContractRemoved, error) {
	s, err := NewSetuprun(c.be, req.Code, req.Now)
	if err != nil {
		return ContractRemoved{}, err
	}
	if s.P.Target == nil || s.P.Engine == nil {
		return ContractRemoved{}, &SetuprunRefusalError{Code: string(setupcode.RefusalInvalid), Message: msgNotARemovalCode}
	}
	if err := CheckConnTarget(s.P, at); err != nil {
		return ContractRemoved{}, err
	}
	return c.RunRemove(ctx, conn)
}

// msgNotARemovalCode refuses a code with no target or no engine key on the
// Remove tab: it is not one basalt init --remove makes.
const msgNotARemovalCode = "This link is not a removal link of a bot's computer. Ask your bot for a new one."

// removalPrefix is the installed guard's prefix, or the default; a
// basalt_meta whose owner is not a guard role is refused PREFIX_MISMATCH.
func (c Contract) removalPrefix(ctx context.Context, tx Querier) (string, error) {
	return InstalledRemovalPrefix(ctx, c.be, tx, guardmodel.DefaultPrefix)
}
