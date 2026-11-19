package child

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// starttime is read after the command's last ')', whatever the command
// holds.
func TestParseStatStart(t *testing.T) {
	tail := " S 1 100 100 0 -1 4194560 120 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10"
	for _, comm := range []string{"(p)", "(a b)", "(a) b (c)", "())"} {
		got, err := parseStatStart([]byte("4242 " + comm + tail))
		require.NoError(t, err, comm)
		require.Equal(t, "987654", got, comm)
	}
	for _, bad := range []string{"", "4242 p S 1", "4242 (p) S 1 2", "4242 (p)" + " S 1 100 100 0 -1 4194560 120 0 0 0 1 2 0 0 20 0 1 0 98x 1000"} {
		_, err := parseStatStart([]byte(bad))
		require.ErrorIs(t, err, errNoStart, bad)
	}
}
