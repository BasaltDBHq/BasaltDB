package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTerminalTextKeepsLinesAndTabsAndEscapesControls(t *testing.T) {
	t.Parallel()
	require.Equal(t,
		"a\nb\tc<U+001B>[2K<U+001B>]0;t<U+0007><U+007F><U+009B>d<U+000D><U+202E><0xFF>",
		TerminalText("a\nb\tc\x1b[2K\x1b]0;t\x07\x7f\u009bd\r\u202e\xff"))
	require.Equal(t, "note 5 — 日本 🚀 José\n", TerminalText("note 5 — 日本 🚀 José\n"))
}
