package revert_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec/linkcodectest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
)

// A long link never carries rescopeNonce, revealNonce or columns: only the
// engine serves them. The Go parser refuses them as the pages do.
func TestParseRequestRefusesNonces(t *testing.T) {
	t.Parallel()
	lines := revertLines()
	base := revert.Request{RevertID: revertID, Binding: bindingText(lines), Lines: lines}
	frag, err := linkcodectest.Encode(linkcodec.Format1, base)
	require.NoError(t, err)
	_, _, err = reverttest.ParseRequest(frag)
	require.NoError(t, err)
	for name, req := range map[string]revert.Request{
		"rescopeNonce": {RevertID: base.RevertID, Binding: base.Binding, Lines: lines, RescopeNonce: seq(16, 1)},
		"revealNonce":  {RevertID: base.RevertID, Binding: base.Binding, Lines: lines, RevealNonce: seq(16, 1)},
		"columns":      {RevertID: base.RevertID, Binding: base.Binding, Lines: lines, Columns: approval.ColumnOrder{"public.leads": {"id"}}},
	} {
		frag, err := linkcodectest.Encode(linkcodec.Format1, req)
		require.NoError(t, err)
		_, _, err = reverttest.ParseRequest(frag)
		require.ErrorIs(t, err, approval.ErrInvalid, name)
	}
}

// A link that names columns at all is refused, an empty or null one too.
func TestParseRequestRefusesEmptyColumns(t *testing.T) {
	t.Parallel()
	lines := revertLines()
	for _, columns := range []any{nil, map[string]any{}, []any{}} {
		frag, err := linkcodectest.Encode(linkcodec.Format1, map[string]any{
			"revertId": revertID, "binding": bindingText(lines), "lines": lines, "columns": columns,
		})
		require.NoError(t, err)
		_, _, err = reverttest.ParseRequest(frag)
		require.ErrorIs(t, err, approval.ErrInvalid, "%v", columns)
	}
}
