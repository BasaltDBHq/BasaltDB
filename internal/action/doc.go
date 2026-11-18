// Package action is the vocabulary the agent service speaks to its store:
// the runs, reads, writes and refusals of an agent, as plain structs. It
// names no database: a store adapter maps these types to its own at its
// edge. It imports only the standard library, uuid and pkg/pagination.
package action
