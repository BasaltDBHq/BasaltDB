package vault

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// countingReader is an endless message that counts what was read of it.
type countingReader struct{ n int64 }

func (r *countingReader) Read(p []byte) (int, error) {
	r.n += int64(len(p))
	return len(p), nil
}

func TestReadBoundedReadsNoMoreThanItsLimit(t *testing.T) {
	t.Parallel()
	for _, limit := range []int{channel.Message1Len, maxControl, channel.FrameMax, maxRoute} {
		r := &countingReader{}
		data, over, err := readBounded(r, limit)
		require.NoError(t, err)
		require.True(t, over)
		require.Nil(t, data)
		require.LessOrEqual(t, r.n, int64(limit)+1, "read past the limit before refusing")
	}
	data, over, err := readBounded(bytes.NewReader(make([]byte, channel.Message1Len)), channel.Message1Len)
	require.NoError(t, err)
	require.False(t, over)
	require.Len(t, data, channel.Message1Len)
}

func TestReadRouteHeader(t *testing.T) {
	t.Parallel()
	msg := append([]byte{wireVersion, typeRoute}, bytes.Repeat([]byte{7}, sidLen)...)
	id, err := readRouteHeader(bytes.NewReader(msg))
	require.NoError(t, err)
	require.Equal(t, sid(bytes.Repeat([]byte{7}, sidLen)), id)

	_, err = readRouteHeader(bytes.NewReader(msg[:routeHeaderLen-1]))
	require.Equal(t, closedError{channel.ErrProtocol}, err)
	_, err = readRouteHeader(io.MultiReader(bytes.NewReader([]byte{2, typeRoute}), bytes.NewReader(make([]byte, sidLen))))
	require.Equal(t, closedError{channel.ErrUnsupportedVersion}, err)
}

func TestBackoffCeiling(t *testing.T) {
	t.Parallel()
	c := &Client{opts: Options{BackoffMin: time.Second, BackoffMax: 60 * time.Second}}
	s := time.Second
	want := []time.Duration{s, 2 * s, 4 * s, 8 * s, 16 * s, 32 * s, 60 * s, 60 * s}
	for attempt, w := range want {
		require.Equal(t, w, c.backoffCeiling(attempt), attempt)
	}
	require.Equal(t, 60*time.Second, c.backoffCeiling(1<<20))
}

func TestFullJitter(t *testing.T) {
	t.Parallel()
	seen := map[int64]bool{}
	for range 200 {
		d := fullJitter(time.Second)
		require.GreaterOrEqual(t, d, time.Duration(0))
		require.LessOrEqual(t, d, time.Second)
		seen[int64(d)] = true
	}
	require.Greater(t, len(seen), 100, "waits are spread, not fixed")
	require.Equal(t, time.Duration(0), fullJitter(0))
}

func TestSessionPhaseLimits(t *testing.T) {
	t.Parallel()
	s := newSessions(time.Second, time.Now)
	limit, _, waiting := s.limit(sid{1})
	require.Equal(t, channel.FrameMax, limit)
	require.False(t, waiting)
	require.Zero(t, s.add(sid{1}, channel.LinkToken{9}))
	limit, token, waiting := s.limit(sid{1})
	require.Equal(t, channel.Message1Len, limit)
	require.Equal(t, channel.LinkToken{9}, token)
	require.True(t, waiting)
}
