package revert

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// A reject note is text the agent reads and may show the person: newlines
// and tabs pass; every other control character and every bidirectional
// control is refused.
func TestRejectNoteRefusesControlCharacters(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"leave it", "line one\nline two\tend", "é 中文 👩‍💻", strings.Repeat("é", 500)} {
		got, err := rejectNote(&ok)
		require.NoError(t, err, "%q", ok)
		require.Equal(t, ok, got)
	}
	for name, bad := range map[string]string{
		"empty":                   "",
		"over 500 characters":     strings.Repeat("x", 501),
		"NUL":                     "a\x00b",
		"ESC":                     "a\x1b[31mred",
		"carriage return":         "a\rb",
		"bell":                    "a\ab",
		"DEL":                     "a\x7fb",
		"C1 (CSI)":                "a\u009bb",
		"right-to-left override":  "a\u202eb",
		"left-to-right embedding": "a\u202ab",
		"first strong isolate":    "a\u2068b",
		"pop directional isolate": "a\u2069b",
		"right-to-left mark":      "a\u200fb",
		"arabic letter mark":      "a\u061cb",
	} {
		_, err := rejectNote(&bad)
		var ae *guidance.ArgumentError
		require.ErrorAs(t, err, &ae, name)
	}
	got, err := rejectNote(nil)
	require.NoError(t, err)
	require.Empty(t, got)
}
