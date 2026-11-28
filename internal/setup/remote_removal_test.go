package setup_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// The removal link opens the connect page's Remove tab with the code, and
// is left out over the budget; its message names the link and keeps the
// admin string on the page.
func TestRemovalLink(t *testing.T) {
	t.Parallel()
	code := "basalt-setup.1.abc.def"
	require.Equal(t, "https://portal.basaltvault.app/connect#remove="+code, setup.RemovalLink(code, 1800))
	require.Empty(t, setup.RemovalLink(code, 20))
	require.Empty(t, setup.RemovalLink(code, 0))
	msg, links := setup.RemovalMessage("Remove BasaltDB from the database shop on db.example.com and from bot's computer.", setup.RemovalLink(code, 1800))
	require.Len(t, links, 1)
	require.Equal(t, setup.LabelRemove, links[0].Label)
	require.True(t, strings.Contains(msg, "#remove="+code))
	require.Contains(t, msg, "Never paste your database password into this chat")
}
