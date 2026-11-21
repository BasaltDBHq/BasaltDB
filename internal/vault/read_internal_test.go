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
	s := newSessions(time.Second, time.Now, nil)
	ph, _ := s.lookup(sid{1})
	require.Equal(t, phaseNone, ph)
	code, _ := s.add(sid{1}, channel.LinkToken{9})
	require.Zero(t, code)
	ph, ss := s.lookup(sid{1})
	require.Equal(t, phaseHello, ph)
	require.Equal(t, channel.LinkToken{9}, ss.token)
	ok, code := s.establish(ss, &established{})
	require.True(t, ok)
	require.Zero(t, code)
	ph, _ = s.lookup(sid{1})
	require.Equal(t, phaseOpen, ph)
}

func TestSessionLate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	s := newSessions(10*time.Second, func() time.Time { return now }, nil)
	code, _ := s.add(sid{1}, channel.LinkToken{})
	require.Zero(t, code)
	_, ss := s.lookup(sid{1})
	now = now.Add(10*time.Second - time.Nanosecond)
	require.False(t, s.late(ss))
	now = now.Add(time.Nanosecond)
	require.True(t, s.late(ss))
}

// Every token's message 1s count, held or not, up to HandshakesPerLink per
// HandshakeWindow; the counters stay bounded whatever tokens arrive.
func TestHandshakeRate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	s := newSessions(10*time.Second, func() time.Time { return now }, nil)
	for range HandshakesPerLink {
		require.True(t, s.allowHandshake(channel.LinkToken{1}))
	}
	require.False(t, s.allowHandshake(channel.LinkToken{1}))
	require.True(t, s.allowHandshake(channel.LinkToken{2}), "another token has its own count")
	now = now.Add(HandshakeWindow)
	require.True(t, s.allowHandshake(channel.LinkToken{1}), "the window moved on")

	for i := range maxTrackedTokens {
		s.allowHandshake(channel.LinkToken{3, byte(i), byte(i >> 8)})
	}
	require.LessOrEqual(t, len(s.handshakes), maxTrackedTokens)
	now = now.Add(HandshakeWindow)
	require.True(t, s.allowHandshake(channel.LinkToken{4}), "old counters are dropped when full")
	require.Len(t, s.handshakes, 1)
}

// The session limit per link counts established sessions of the token.
func TestSessionsPerLink(t *testing.T) {
	t.Parallel()
	s := newSessions(10*time.Second, time.Now, nil)
	for i := range MaxSessionsPerLink + 1 {
		code, _ := s.add(sid{byte(i)}, channel.LinkToken{7})
		require.Zero(t, code)
	}
	for i := range MaxSessionsPerLink {
		_, ss := s.lookup(sid{byte(i)})
		ok, _ := s.establish(ss, &established{})
		require.True(t, ok)
	}
	_, ss := s.lookup(sid{MaxSessionsPerLink})
	ok, code := s.establish(ss, &established{})
	require.False(t, ok)
	require.Equal(t, channel.ErrSessionLimit, code)
	require.Len(t, s.ofToken(channel.LinkToken{7}), MaxSessionsPerLink+1)
}

// A widen moves the session's link slot to the new token: the new token's
// count includes it, the old token keeps none, and the session ending
// frees the new token's slot.
func TestSessionLimitFollowsARotatedToken(t *testing.T) {
	t.Parallel()
	s := newSessions(10*time.Second, time.Now, newTally())
	oldTok, newTok := channel.LinkToken{1}, channel.LinkToken{2}
	code, _ := s.add(sid{1}, oldTok)
	require.Zero(t, code)
	_, ss := s.lookup(sid{1})
	ok, _ := s.establish(ss, &established{})
	require.True(t, ok)

	cn := &conn{sessions: s}
	ss.est.link = SessionLink{}
	cn.rotate(ss, newTok)
	require.Zero(t, s.tally.established[oldTok], "the old token holds no slot")
	for i := 1; i < MaxSessionsPerLink; i++ {
		code, _ := s.add(sid{10, byte(i)}, newTok)
		require.Zero(t, code)
		_, o := s.lookup(sid{10, byte(i)})
		ok, _ := s.establish(o, &established{})
		require.True(t, ok)
	}
	code, _ = s.add(sid{20}, newTok)
	require.Zero(t, code)
	_, o := s.lookup(sid{20})
	ok, code = s.establish(o, &established{})
	require.False(t, ok, "the rotated session counts: a fifth is refused")
	require.Equal(t, channel.ErrSessionLimit, code)

	s.take(sid{1})
	require.Equal(t, MaxSessionsPerLink-1, s.tally.established[newTok])
	require.Zero(t, s.tally.established[oldTok])
}

// A widen that finishes after its session ended moves no slot: the session
// is gone from the table, so the new token gains nothing that nothing
// would release.
func TestRotateAfterTheSessionEndedMovesNoSlot(t *testing.T) {
	t.Parallel()
	s := newSessions(10*time.Second, time.Now, newTally())
	oldTok, newTok := channel.LinkToken{1}, channel.LinkToken{2}
	code, _ := s.add(sid{1}, oldTok)
	require.Zero(t, code)
	_, ss := s.lookup(sid{1})
	ok, _ := s.establish(ss, &established{})
	require.True(t, ok)
	require.NotNil(t, s.take(sid{1}))

	(&conn{sessions: s}).rotate(ss, newTok)
	require.Zero(t, s.tally.established[newTok])
	require.Zero(t, s.tally.established[oldTok])
	require.Zero(t, s.tally.total)
}
