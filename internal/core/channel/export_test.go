package channel

import (
	"testing"
)

// Test-only exports for the external tests.

func LoadVectors[T any](t *testing.T, name, kind string) []T { return loadVectors[T](t, name, kind) }

var (
	B64     = b64
	Outcome = outcome
)
