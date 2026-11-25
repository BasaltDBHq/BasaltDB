package pii

import "github.com/basaltdbhq/basaltdb/internal/core/piistore"

// Column is a field the agents can read, as the classifier sees it.
type Column = piistore.Column

// Sample is what reading a field's values gave.
type Sample = piistore.Sample

// SampleRows is how many non-null values are sampled per field.
const SampleRows = piistore.SampleRows

// Why a sample could not be read (Sample.Unavailable).
const (
	UnavailableTimeout    = piistore.UnavailableTimeout
	UnavailableNoReadable = piistore.UnavailableNoReadable
)
