// Package pagination holds what every list in BasaltDB shares: the limit,
// cursor and sort arguments (Params), the whitelist check for a sort
// (ParseSort), and opaque keyset cursors. Lists are paged by keyset, never by
// offset (AGENTS.md, Lists). A cursor is base64url JSON of the last row's key:
// its id, its name or a sequence number.
package pagination

// Defaults for Params.Limit. The handler applies them with
// ApplyDefaultsAndClamp; the repositories trust the clamped value.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Params is embedded in every list-params struct (MCP tool args, CLI flags).
type Params struct {
	Limit  int    `query:"limit" json:"limit,omitempty"`
	Cursor string `query:"cursor" json:"cursor,omitempty"`
	Sort   string `query:"sort" json:"sort,omitempty"`
}

// ApplyDefaultsAndClamp sets default limit and caps at MaxLimit. Call once
// the tool or CLI arguments are parsed, before the query runs.
func (p *Params) ApplyDefaultsAndClamp() {
	if p.Limit <= 0 {
		p.Limit = DefaultLimit
	}
	if p.Limit > MaxLimit {
		p.Limit = MaxLimit
	}
}

// Page is a single list response page.
type Page[T any] struct {
	Items      []T
	NextCursor string
	TotalCount *int64
}

// MCPList wraps items for MCP tools.
type MCPList[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

func ToMCP[T any](p Page[T]) MCPList[T] {
	return MCPList[T]{Items: p.Items, NextCursor: p.NextCursor}
}
