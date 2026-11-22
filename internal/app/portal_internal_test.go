package engine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

func TestNoPortalCheckWithoutAPortalInTheConfig(t *testing.T) {
	t.Parallel()
	require.Nil(t, newPortalChecker(links.DefaultLocal, t.TempDir(), quietLog(), time.Now), "the engine's own pages are not checked")
	require.Nil(t, newPortalChecker("", t.TempDir(), quietLog(), time.Now))
}

func TestAPortalCheckIsMadeForThePortal(t *testing.T) {
	t.Parallel()
	c := newPortalChecker(links.Portal, t.TempDir(), quietLog(), time.Now)
	require.NotNil(t, c)
	_, ok := c.PortalFinding()
	require.False(t, ok, "nothing is reported before the first check")
}
