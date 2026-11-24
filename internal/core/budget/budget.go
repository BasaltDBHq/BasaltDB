// Package budget is the size budget one tool call's reads are charged
// against (CONTRACT.md, QUERY_TIMEOUT SIZE_LIMIT): the call carries it in its
// context, and a charge past it reports ErrSizeLimit. A context with no
// budget (the person's CLI, upkeep) reads unbounded. It names no database:
// the postgres adapter charges rows to it.
package budget

import (
	"context"
	"fmt"
	"sync/atomic"
)

// MaxBytes bounds what one call's reads cost, summed over their rows: the
// 16 MiB the shim accepts in one line.
const MaxBytes = 16 << mibShift

// mibShift turns bytes into MiB.
const mibShift = 20

// ErrSizeLimit is a read stopped because the call's reads came to more than
// MaxBytes.
var ErrSizeLimit = fmt.Errorf("the query result is larger than %d MiB", MaxBytes>>mibShift)

// Budget is one call's budget. Reads of the call may run concurrently.
type Budget struct {
	used atomic.Int64
	max  int64
}

type budgetKey struct{}

// With returns ctx carrying a new budget of MaxBytes for one call.
func With(ctx context.Context) context.Context {
	return WithMax(ctx, MaxBytes)
}

// WithMax returns ctx carrying a new budget of max bytes: With's, or a
// small one in tests.
func WithMax(ctx context.Context, maxBytes int64) context.Context {
	return context.WithValue(ctx, budgetKey{}, &Budget{max: maxBytes})
}

// Without returns ctx with no budget: the reads made with it are not charged.
func Without(ctx context.Context) context.Context {
	return context.WithValue(ctx, budgetKey{}, (*Budget)(nil))
}

// Ensure returns ctx with a budget: its own when it has one, else a new one.
func Ensure(ctx context.Context) context.Context {
	if From(ctx) != nil {
		return ctx
	}
	return With(ctx)
}

// From returns ctx's budget, nil when it has none.
func From(ctx context.Context) *Budget {
	b, _ := ctx.Value(budgetKey{}).(*Budget)
	return b
}

// Max is the most bytes b allows.
func (b *Budget) Max() int64 { return b.max }

// Charge adds cost to b and reports ErrSizeLimit once the total is over
// MaxBytes. A nil budget charges nothing.
func (b *Budget) Charge(cost int) error {
	if b == nil {
		return nil
	}
	if b.used.Add(int64(cost)) > b.max {
		return ErrSizeLimit
	}
	return nil
}
