package passkey_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

func TestFitLabelKeepsNamesThatFit(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"BasaltDB · demo_bot",
		"BasaltDB · " + strings.Repeat("a", passkey.MaxLabelLen-len("BasaltDB · ")),
		strings.Repeat("é", passkey.MaxLabelLen/2),
	} {
		require.Equal(t, s, passkey.FitLabel(s))
	}
}

func TestFitLabelCutsLongNamesOnARuneWithAnEllipsis(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"BasaltDB · " + strings.Repeat("a", 55),
		"BasaltDB · " + strings.Repeat("a", passkey.MaxLabelLen-len("BasaltDB · ")+1),
		strings.Repeat("é", passkey.MaxLabelLen),
		strings.Repeat("a", 60) + "日本語のデータベース",
		strings.Repeat("😀", 40),
	} {
		got := passkey.FitLabel(s)
		require.LessOrEqual(t, len(got), passkey.MaxLabelLen, s)
		require.True(t, utf8.ValidString(got), s)
		require.True(t, strings.HasSuffix(got, "…"), got)
		require.True(t, strings.HasPrefix(s, strings.TrimSuffix(got, "…")), got)
		require.Greater(t, len(got), passkey.MaxLabelLen-utf8.UTFMax-len("…"), "cut no more than one rune short: %q", got)
		_, err := passkey.RegistrationRequestFor(make([]byte, passkey.ChallengeLen), make([]byte, passkey.UserIDLen), got, got)
		require.NoError(t, err)
	}
}
