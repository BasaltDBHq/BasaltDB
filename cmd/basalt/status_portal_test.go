package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/portalcheck"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

func TestStatusReadsTheSavedPortalCheckOnlyForThePortal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	saved := `{"portalUrl":"` + links.Portal + `","checkedAt":"2026-11-14T09:00:00Z","findings":[{"path":"style.css","status":"DIFFERS"}],"total":1}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, portalcheck.FileName), []byte(saved), 0o600))

	r := savedPortalCheck(dir, links.Portal)
	require.NotNil(t, r)
	f, ok := r.PortalFinding()
	require.True(t, ok)
	require.True(t, f.Mismatch)
	require.Equal(t, "1 DIFFERS", f.Summary)

	require.Nil(t, savedPortalCheck(dir, links.DefaultLocal), "no portal in the config: no check, whatever the file says")
}
