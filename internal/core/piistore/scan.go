package piistore

import (
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
)

// ScanTarget is one resource the dictionary scan reads: its IDENTIFIER
// fields, in the order the scan's value callback numbers them.
type ScanTarget struct {
	Resource agentstore.ResourceRef
	// Namespace and Name are the resource's printed names (never PII).
	Namespace, Name string
	Fields          []FieldClass
}

// Why the scan skips one resource and goes on, instead of failing the
// cycle. The store's adapter wraps its own error in one of them, so the
// cause stays readable.
var (
	// ErrUnreadable is a resource that is gone, or that the agent may no
	// longer read.
	ErrUnreadable = errors.New("the agent can no longer read the resource")
	// ErrTooSlow is a resource with no key to page by whose full read
	// exceeded the agent's statement timeout.
	ErrTooSlow = errors.New("the resource has no key to page by and a full read exceeded the statement timeout")
)
