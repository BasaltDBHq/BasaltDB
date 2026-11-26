// Package action holds the ledger types every domain shares: the runs,
// reads, writes and refusals of an agent and the approval and revert
// records, as plain structs. A domain's own store port types live in its
// core/<domain>store package. It names no database: a store adapter maps
// these types to its own at its edge. It imports only the standard
// library, uuid, internal/lib/pagination and internal/core/largevalue.
package action
