package pagination

import (
	"fmt"
	"strings"
)

// SortSpec whitelists sort query values for one list resource.
// SortSpec says which sorts a list accepts: Default is used when the caller
// gives none, and Allowed holds every accepted value, with its "-" prefix for
// descending order.
type SortSpec struct {
	Default string
	Allowed map[string]struct{}
}

// ParsedSort is a whitelisted column and direction.
// ParsedSort is a sort split into its column and direction.
type ParsedSort struct {
	Column string
	Desc   bool
}

// ParseSort validates p.Sort against spec and returns the SQL column + direction.
// ParseSort checks Params.Sort against spec (spec.Default when empty) and
// returns the column and direction. A value not in spec.Allowed is an error,
// so a caller can never name a column the list did not offer.
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
