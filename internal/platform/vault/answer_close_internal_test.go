package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// closeRecorder is a carrier that records every SESSION_CLOSE.
type closeRecorder struct {
	mu     sync.Mutex
	closes []channel.CloseError
}

func (r *closeRecorder) send(context.Context, sid, []byte) error { return nil }

func (r *closeRecorder) closeSession(_ context.Context, _ sid, code channel.CloseError) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closes = append(r.closes, code)
	return nil
}

func (r *closeRecorder) got() []channel.CloseError {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]channel.CloseError(nil), r.closes...)
}

// establishedConn is a socket holding one established session whose
// channel is the engine's end of a real handshake; page is the page's end.
func establishedConn(t *testing.T) (*conn, *session, *channel.Session, *closeRecorder) {
	t.Helper()
	secret := make([]byte, channel.SecretLen)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	lk, err := channel.DeriveLink(base64.RawURLEncoding.EncodeToString(secret))
	require.NoError(t, err)
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	init, m1, err := channel.WriteHello(channel.TransportRelay, lk)
	require.NoError(t, err)
	resp, err := channel.ReadHello(m1, channel.HelloCheck{
		Transport: channel.TransportRelay, SessionToken: &lk.Token,
		Lookup: func(channel.LinkToken) (channel.PSK, bool) { return lk.PSK, true },
	})
	require.NoError(t, err)
	m2, engine, err := resp.WriteWelcome(keys)
	require.NoError(t, err)
	page, _, err := init.ReadWelcome(m2)
	require.NoError(t, err)

	rec := &closeRecorder{}
	cn := &conn{
		c:        &Client{opts: Options{Now: time.Now, Log: slog.New(slog.DiscardHandler)}},
		sessions: newSessions(time.Minute, time.Now, nil), out: rec, ctx: context.Background(),
	}
	id := sid{1}
	code, _ := cn.sessions.add(id, lk.Token)
	require.Zero(t, code)
	ss := cn.sessions.open[id]
	require.True(t, cn.sessions.tally.establish(lk.Token), "the session takes its link's slot, as an established one does")
	_, cancel := context.WithCancel(context.Background())
	ss.est = &established{cancel: cancel, idle: time.NewTimer(time.Hour), life: time.NewTimer(time.Hour), work: make(chan Request, 1), ch: engine}
	return cn, ss, page, rec
}

// The order the hostile Vault test hit under load: the read loop refuses a
// duplicated frame (which fails the session's channel), and the worker,
// answering the first copy, cannot seal its answer and ends the session
// before the read loop does. The session ends once, with FRAME_INVALID: the
// worker takes the code its error carries, and the read loop's end finds
// the session gone and tells the Vault nothing more.
func TestAnAnswerAfterARefusedFrameEndsWithFrameInvalidOnce(t *testing.T) {
	t.Parallel()
	cn, ss, page, rec := establishedConn(t)
	frame, err := page.Seal([]byte(`{"type":"REQUEST","id":1,"method":"GET","path":"/x","headers":{},"body":"","more":false}`))
	require.NoError(t, err)

	// The read loop: the first copy opens, the duplicate does not.
	ss.est.mu.Lock()
	_, err = ss.est.ch.Open(frame)
	require.NoError(t, err)
	_, err = ss.est.ch.Open(frame)
	ss.est.mu.Unlock()
	require.ErrorIs(t, err, channel.ErrFrameInvalid)

	// The worker answers first, as work() does on a failed answer.
	err = cn.respond(context.Background(), ss, 1, Response{Status: 200, Body: []byte("{}")})
	require.Error(t, err)
	cn.endAsync(ss.id, answerCloseCode(err))

	// Then the read loop ends the session for the frame it refused.
	require.NoError(t, cn.end(context.Background(), ss.id, channel.ErrFrameInvalid))
	require.Equal(t, []channel.CloseError{channel.ErrFrameInvalid}, rec.got())
}

// The other order: the read loop ends the session first; the worker's end
// finds it gone. Still one SESSION_CLOSE, with FRAME_INVALID.
func TestARefusedFrameEndsTheSessionOnceWhenTheReadLoopIsFirst(t *testing.T) {
	t.Parallel()
	cn, ss, _, rec := establishedConn(t)
	require.NoError(t, cn.end(context.Background(), ss.id, channel.ErrFrameInvalid))
	err := cn.respond(context.Background(), ss, 1, Response{Status: 200, Body: []byte("{}")})
	require.Error(t, err)
	cn.endAsync(ss.id, answerCloseCode(err))
	require.Equal(t, []channel.CloseError{channel.ErrFrameInvalid}, rec.got())
}

func TestAnswerCloseCode(t *testing.T) {
	t.Parallel()
	require.Equal(t, channel.ErrFrameInvalid, answerCloseCode(channel.ErrFrameInvalid))
	require.Equal(t, channel.ErrTooLarge, answerCloseCode(errors.Join(errors.New("seal"), channel.ErrTooLarge)))
	require.Equal(t, channel.ErrProtocol, answerCloseCode(errors.New("write: broken pipe")))
}
