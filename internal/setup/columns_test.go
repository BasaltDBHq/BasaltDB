package setup_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// A column name is passed on only when it could be a Postgres identifier
// and holds no control character.
func TestPlainColumn(t *testing.T) {
	t.Parallel()
	require.True(t, setup.PlainColumn("email"))
	require.True(t, setup.PlainColumn(strings.Repeat("a", 63)))
	require.True(t, setup.PlainColumn("adresse électronique"))
	require.False(t, setup.PlainColumn(""))
	require.False(t, setup.PlainColumn(strings.Repeat("a", 64)))
	require.False(t, setup.PlainColumn("email\x1fx"))
	require.False(t, setup.PlainColumn("email\n"))
}
