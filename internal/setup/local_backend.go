package setup

// CatalogTable is one table of an install's listing, as the catalog has it
// (an alias of the struct, as the store declares it).
type CatalogTable = struct {
	Name  string
	Owner string
	Mine  bool
	Keyed bool
	Plain bool
}
