package pagination

import (
	"fmt"
	"strings"
)

// SortSpec whitelists sort query values for one list resource.
type SortSpec struct {
	Default string
	Allowed map[string]struct{}
}

// ParsedSort is a whitelisted column and direction.
type ParsedSort struct {
	Column string
	Desc   bool
}

// ParseSort validates p.Sort against spec and returns the SQL column + direction.
func (p *Params) ParseSort(spec SortSpec) (ParsedSort, error) {
	sort := p.Sort
	if sort == "" {
		sort = spec.Default
	}
	if _, ok := spec.Allowed[sort]; !ok {
		return ParsedSort{}, fmt.Errorf("unknown sort %q", sort)
	}
	desc := strings.HasPrefix(sort, "-")
	col := strings.TrimPrefix(sort, "-")
	return ParsedSort{Column: col, Desc: desc}, nil
}

// Sort query tokens (whitelisted in SortSpec.Allowed).
const (
	sortAscSeq  = "seq"
	sortDescSeq = "-seq"
)

// ChangeSortSpec is the change log ordering (oldest first by default).
var ChangeSortSpec = SortSpec{
	Default: sortAscSeq,
	Allowed: map[string]struct{}{sortAscSeq: {}, sortDescSeq: {}},
}
