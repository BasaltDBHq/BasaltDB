package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// What the engine's local pages ask of an agent (CONTRACT.md, Local
// pages): the request a short link stands for, and the relay of the
// person's signature with this agent's credential. The relay decides
// nothing: Postgres verifies the passkey signature.

// ErrNotThisAgent is an approval or revert this agent's role cannot see:
// another agent's, or none.
var ErrNotThisAgent = errors.New("not one of this agent's approvals or reverts")

// ColumnOrder reads tables' columns in table order (attnum).
type ColumnOrder interface {
	// ColumnOrder maps each table name, as the lines spell it, to its
	// columns; a table it cannot find is left out.
	ColumnOrder(ctx context.Context, tables []string) (map[string][]string, error)
}

// columnsOf is the column order of the tables lines name, for the pages'
// display only (CONTRACT.md, Local pages): never signed, and a failure
// only costs the order, so it is logged and nil is returned.
func (dc *deliveryCase) columnsOf(ctx context.Context, lines []string) approval.ColumnOrder {
	if !dc.approvals.hasColumns() {
		return nil
	}
	seen := map[string]bool{}
	var tables []string
	for _, l := range lines {
		var line struct {
			Table string `json:"table"`
		}
		if json.Unmarshal([]byte(l), &line) != nil || line.Table == "" || seen[line.Table] {
			continue
		}
		seen[line.Table] = true
		tables = append(tables, line.Table)
	}
	if len(tables) == 0 {
		return nil
	}
	cols, err := dc.approvals.ColumnOrder(ctx, tables)
	if err != nil {
		dc.core.Log.WarnContext(ctx, "pages: column order not read; the page shows the rows' order", "err", err)
		return nil
	}
	if len(cols) == 0 {
		return nil
	}
	return cols
}

// CheckLink reports whether secret is the live link secret of one of this
// agent's items.
func (dc *deliveryCase) CheckLink(id uuid.UUID, secret string) bool {
	return dc.deps.Links.Check(id, secret)
}

// issuedLink is a newly issued short link; this engine must serve the
// pages.
func (dc *deliveryCase) issuedLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) (string, error) {
	link, err := dc.localLink(page, id, expires)
	if err != nil {
		return "", err
	}
	if link == "" {
		return "", &toolresult.ToolError{Code: guidance.CodeUnavailable, Message: "this engine serves no pages"}
	}
	return link, nil
}
