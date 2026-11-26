package links

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
// nothing: the guard verifies the passkey signature.

// ErrNotThisAgent is an approval or revert this agent's role cannot see:
// another agent's, or none.
var ErrNotThisAgent = errors.New("not one of this agent's approvals or reverts")

// ColumnOrder reads resources' fields in the order their store keeps them.
type ColumnOrder interface {
	// ColumnOrder maps each resource name, as the lines spell it, to its
	// field names in the store's order; a resource it cannot find is left
	// out.
	ColumnOrder(ctx context.Context, resources []string) (map[string][]string, error)
}

// FieldsOf is the field order of the resources lines name, for the pages'
// display only (CONTRACT.md, Local pages): never signed, and a failure
// only costs the order, so it is logged and nil is returned.
func (dc *Service) FieldsOf(ctx context.Context, lines []string) approval.FieldOrder {
	if !dc.approvals.HasColumns() {
		return nil
	}
	seen := map[string]bool{}
	var resources []string
	for _, l := range lines {
		var line struct {
			Resource string `json:"resource"`
		}
		if json.Unmarshal([]byte(l), &line) != nil || line.Resource == "" || seen[line.Resource] {
			continue
		}
		seen[line.Resource] = true
		resources = append(resources, line.Resource)
	}
	if len(resources) == 0 {
		return nil
	}
	cols, err := dc.approvals.ColumnOrder(ctx, resources)
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
func (dc *Service) CheckLink(id uuid.UUID, secret string) bool {
	return dc.deps.Links.Check(id, secret)
}

// IssuedLink is a newly issued short link; this engine must serve the
// pages.
func (dc *Service) IssuedLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) (string, error) {
	link, err := dc.localLink(page, id, expires)
	if err != nil {
		return "", err
	}
	if link == "" {
		return "", &toolresult.ToolError{Code: guidance.CodeUnavailable, Message: "this engine serves no pages"}
	}
	return link, nil
}
