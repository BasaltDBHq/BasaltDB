package revert_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// A long link never carries rescopeNonce or revealNonce: only the engine
// serves them. The Go parser refuses both as the pages do.
func TestParseRequestRefusesNonces(t *testing.T) {
	t.Parallel()
	lines := revertLines()
	base := revert.Request{RevertID: revertID, Binding: bindingText(lines), Lines: lines}
	frag, err := linkcodec.Encode(linkcodec.Format1, base)
	require.NoError(t, err)
	_, _, err = revert.ParseRequest(frag)
	require.NoError(t, err)
	for name, req := range map[string]revert.Request{
		"rescopeNonce": {RevertID: base.RevertID, Binding: base.Binding, Lines: lines, RescopeNonce: seq(16, 1)},
		"revealNonce":  {RevertID: base.RevertID, Binding: base.Binding, Lines: lines, RevealNonce: seq(16, 1)},
	} {
		frag, err := linkcodec.Encode(linkcodec.Format1, req)
		require.NoError(t, err)
		_, _, err = revert.ParseRequest(frag)
		require.ErrorIs(t, err, revert.ErrInvalid, name)
	}
}
