// Package shim is the agent's MCP server process: it relays the MCP client's
// stdio to the engine's Unix socket for that agent and back. It holds no
// secret and never parses SQL, so it starts instantly and has nothing an
// agent could take from it. When the socket does not answer, it answers
// the client itself from a fallback server (CONTRACT.md, Next steps,
// Startup failures) and tries the socket again on the next message.
package shim

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

const (
	scannerInitSize = 64 * 1024
	// scannerMaxSize is the longest message either side may send, as the
	// engine's MCP server reads it.
	scannerMaxSize = 16 << 20
)

// Fallback answers what the engine does not (agent.EngineDownServer).
type Fallback interface {
	// ServeLine answers one JSON-RPC message the engine never received.
	ServeLine(ctx context.Context, out io.Writer, line []byte) error
	// Abandoned answers a request the engine received but closed the
	// connection without answering: always an error, never a replay.
	Abandoned(ctx context.Context, out io.Writer, line []byte) error
}

// Serve relays each message the client writes to in, one JSON-RPC message
// per line, to the engine at socketPath, and every line the engine answers
// to out. A message that finds no engine (the socket does not answer, or the
// engine closed the connection) is answered by fallback, and the next one
// tries the socket again, so an engine that starts later is used from then
// on. A request the engine received but did not answer before it closed the
// connection is answered by fallback.Abandoned, so the client never waits
// forever. When in ends, the write side of the socket is closed so the
// engine finishes its answers; Serve returns after them, or when ctx is
// done. An engine connection that ends in an error other than a clean close
// is reported when it is the last one.
func Serve(ctx context.Context, socketPath string, fallback Fallback, in io.Reader, out io.Writer) error {
	if fallback == nil {
		panic("shim: fallback server required")
	}
	r := &relay{path: socketPath, fallback: fallback, out: &lineWriter{w: out}}
	defer r.close()

	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go readLines(ctx, in, lines, readErr)
	for {
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-lines:
			if !ok {
				if err := <-readErr; err != nil {
					return fmt.Errorf("read from the MCP client: %w", err)
				}
				return r.finish(ctx)
			}
			if err := r.send(ctx, line); err != nil {
				return err
			}
		}
	}
}

// readLines sends each non-empty line of in on lines, then closes it after
// putting the read error (nil at EOF) on errs.
func readLines(ctx context.Context, in io.Reader, lines chan<- []byte, errs chan<- error) {
	defer close(lines)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, scannerInitSize), scannerMaxSize)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		select {
		case lines <- append([]byte(nil), line...):
		case <-ctx.Done():
			errs <- nil
			return
		}
	}
	errs <- sc.Err()
}

// relay holds the current engine connection, if any.
type relay struct {
	path     string
	fallback Fallback
	out      *lineWriter
	sess     *session
}

// send forwards line to the engine, dialing when there is no live
// connection, or answers it from the fallback when the engine does not take
// it.
func (r *relay) send(ctx context.Context, line []byte) error {
	if r.sess != nil && r.sess.forward(line) {
		return nil
	}
	r.close()
	sess, err := dial(ctx, r.path, r.out, r.fallback)
	if err == nil {
		r.sess = sess
		if sess.forward(line) {
			return nil
		}
		r.close()
	}
	return r.fallback.ServeLine(ctx, r.out, line)
}

// finish closes the write side of a live connection and waits for the
// engine's last answers.
func (r *relay) finish(ctx context.Context) error {
	if r.sess == nil {
		return nil
	}
	_ = r.sess.conn.CloseWrite()
	select {
	case <-r.sess.done:
		return r.sess.err
	case <-ctx.Done():
		return nil
	}
}

func (r *relay) close() {
	if r.sess == nil {
		return
	}
	r.sess.conn.Close()
	<-r.sess.done
	r.sess = nil
}

// session is one connection to the engine and the goroutine copying its
// answers to the client. It keeps the requests the engine has not answered
// yet, by id, and answers them through the fallback when the connection
// ends.
type session struct {
	conn     *net.UnixConn
	fallback Fallback
	done     chan struct{}
	// err is the read error that ended the session, set before done closes;
	// nil for a clean close.
	err error

	// refusal is the engine's refusal of this OS user (mcp.PeerRefusal),
	// "" when it admitted the peer.
	refusal string

	mu      sync.Mutex
	ended   bool
	pending map[string][]byte
}

func dial(ctx context.Context, path string, out *lineWriter, fallback Fallback) (*session, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("%s is not a Unix socket", path)
	}
	s := &session{conn: conn, fallback: fallback, done: make(chan struct{}), pending: map[string][]byte{}}
	go s.copyAnswers(ctx, out)
	return s, nil
}

// copyAnswers writes each line the engine sends to out until the engine
// closes the connection, then answers what it left unanswered.
func (s *session) copyAnswers(ctx context.Context, out *lineWriter) {
	defer close(s.done)
	defer s.abandon(ctx, out)
	sc := bufio.NewScanner(s.conn)
	sc.Buffer(make([]byte, scannerInitSize), scannerMaxSize)
	for sc.Scan() {
		if msg := mcp.PeerRefusal(sc.Bytes()); msg != "" {
			// Not a request's answer: the requests left pending get its
			// message when the engine closes.
			s.refusal = msg
			continue
		}
		s.answered(sc.Bytes())
		if err := out.writeLine(sc.Bytes()); err != nil {
			s.err = fmt.Errorf("write to the MCP client: %w", err)
			return
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.err = fmt.Errorf("relay from engine: %w", err)
	}
	if s.refusal != "" {
		s.err = errors.New(s.refusal)
	}
}

// abandon ends the session and answers every request still pending.
func (s *session) abandon(ctx context.Context, out *lineWriter) {
	s.mu.Lock()
	s.ended = true
	left := s.pending
	s.pending = nil
	s.mu.Unlock()
	for _, line := range left {
		if req, ok := mcp.RequestOf(line); ok && s.refusal != "" {
			_ = mcp.WriteError(out, req.ID, mcp.ErrCodeServer, s.refusal)
			continue
		}
		_ = s.fallback.Abandoned(context.WithoutCancel(ctx), out, line)
	}
}

// forward hands line to the engine and reports whether the session took
// it: false when the session has ended or the write failed, and the caller
// answers it some other way.
func (s *session) forward(line []byte) bool {
	key := messageID(line)
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return false
	}
	if key != "" {
		s.pending[key] = line
	}
	s.mu.Unlock()
	if _, err := s.conn.Write(append(append([]byte(nil), line...), '\n')); err == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, still := s.pending[key]; key != "" && !still {
		return true // the session ended meanwhile and already answered it
	}
	delete(s.pending, key)
	return false
}

// answered drops the request an engine answer is for.
func (s *session) answered(line []byte) {
	key := messageID(line)
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
}

// messageID is a JSON-RPC message's id in one canonical spelling; "" for a
// notification or a line that is not JSON.
func messageID(line []byte) string {
	var m struct {
		ID any `json:"id"`
	}
	if json.Unmarshal(line, &m) != nil || m.ID == nil {
		return ""
	}
	raw, err := json.Marshal(m.ID)
	if err != nil {
		return ""
	}
	return string(raw)
}

// lineWriter writes whole lines to the client, one at a time: the engine's
// answers and the fallback's never interleave.
type lineWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// Write takes one encoded JSON-RPC message, newline included, from the
// fallback server.
func (l *lineWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (l *lineWriter) writeLine(line []byte) error {
	_, err := l.Write(append(append([]byte(nil), line...), '\n'))
	return err
}
