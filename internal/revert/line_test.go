package revert

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLineForDisplayShowsTimestampsAsUTC(t *testing.T) {
	t.Parallel()
	text := `{"op":"UPDATE","key":{"id":1},"now":{"at":"2026-11-12T14:08:04+02:00"},"set":{"at":"2026-11-12T14:00:00.5+02:00","n":12345678901234567890},"table":"public.leads","action":"RESTORE","cascaded":false,"conflict":null,"changeIds":["0199e1a0-0000-7000-8000-000000000001"]}`
	l, err := ParseLine(text)
	require.NoError(t, err)
	shown := l.ForDisplay()
	require.JSONEq(t, `{"at":"2026-11-12T12:08:04Z"}`, string(shown.Now))
	require.JSONEq(t, `{"at":"2026-11-12T12:00:00.5Z","n":12345678901234567890}`, string(shown.Set))
	require.JSONEq(t, `{"id":1}`, string(shown.Key))
	require.Contains(t, string(l.Set), "+02:00", "the parsed line is not changed")
}
