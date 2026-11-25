package pii

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// quoteIdentifier writes what the driver's Identifier.Sanitize writes.
func TestQuoteIdentifier(t *testing.T) {
	for _, parts := range [][]string{
		{"email"}, {"public", "people"}, {`we"ird`, "Mixed Case"}, {"nul\x00byte"}, {""},
	} {
		require.Equal(t, pgx.Identifier(parts).Sanitize(), quoteIdentifier(parts...), "%q", parts)
	}
}
