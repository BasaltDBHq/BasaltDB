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
	sortAscID          = "id"
	sortDescID         = "-id"
	sortAscCreatedAt   = "createdAt"
	sortDescCreatedAt  = "-createdAt"
	sortAscName        = "name"
	sortDescName       = "-name"
	sortAscSeq         = "seq"
	sortDescSeq        = "-seq"
	sortAscConsumerID  = "consumerId"
	sortDescConsumerID = "-consumerId"
	sortAscMachineID   = "machineId"
	sortDescMachineID  = "-machineId"
	sortAscOrigin      = "origin"
	sortDescOrigin     = "-origin"
)

// RecordSortSpec is the default record list ordering (-id = newest first).
var RecordSortSpec = SortSpec{
	Default: sortDescID,
	Allowed: map[string]struct{}{
		sortAscID: {}, sortDescID: {},
		sortAscCreatedAt: {}, sortDescCreatedAt: {},
	},
}

var CollectionSortSpec = SortSpec{
	Default: sortAscName,
	Allowed: map[string]struct{}{sortAscName: {}, sortDescName: {}},
}

var ChangeSortSpec = SortSpec{
	Default: sortAscSeq,
	Allowed: map[string]struct{}{sortAscSeq: {}, sortDescSeq: {}},
}

var LinkSortSpec = SortSpec{
	Default: sortDescID,
	Allowed: map[string]struct{}{sortAscID: {}, sortDescID: {}},
}

var APIKeySortSpec = SortSpec{
	Default: sortDescCreatedAt,
	Allowed: map[string]struct{}{
		sortAscCreatedAt: {}, sortDescCreatedAt: {},
		sortAscID: {}, sortDescID: {},
	},
}

var ConflictSortSpec = SortSpec{
	Default: sortDescCreatedAt,
	Allowed: map[string]struct{}{
		sortAscCreatedAt: {}, sortDescCreatedAt: {},
		sortAscID: {}, sortDescID: {},
	},
}

var ConsumerCursorSortSpec = SortSpec{
	Default: sortAscConsumerID,
	Allowed: map[string]struct{}{sortAscConsumerID: {}, sortDescConsumerID: {}},
}

var PeerSortSpec = SortSpec{
	Default: sortAscMachineID,
	Allowed: map[string]struct{}{sortAscMachineID: {}, sortDescMachineID: {}},
}

var OriginCursorSortSpec = SortSpec{
	Default: sortAscOrigin,
	Allowed: map[string]struct{}{sortAscOrigin: {}, sortDescOrigin: {}},
}
