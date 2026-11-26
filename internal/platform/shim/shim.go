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
	"sync/atomic"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

const (
	scannerInitSize = 64 * 1024
	// scannerMaxSize is the longest message either side may send, as the
	// engine's MCP server reads it.
	scannerMaxSize = 16 << 20

	// DefaultReconnectWait is long enough for a service manager to restart
	// the engine.
	DefaultReconnectWait = 15 * time.Second
	// DefaultStartWait is how long a message waits for an engine that
	// Options.Start started, or found starting.
	DefaultStartWait = 15 * time.Second
	reconnectPoll    = 100 * time.Millisecond
	retryQueue       = 64
)

// Fallback answers what the engine does not (statusmcp.Server).
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
// is reported when it is the last one, and so is the engine's refusal of
// this OS user, even when that connection ended before a request reached it:
// the requests it declined are answered with the refusal.
//
// An engine that was serving this session and goes away (an upgrade restarts
// it) is waited for, up to DefaultReconnectWait, before the next message
// falls back; a read-only request the engine dropped unanswered is sent once
// more to the engine that returns, and so is any request the engine
// answered as not run because it was restarting (mcpserver.ErrCodeRestarting).
// Nothing else is ever sent twice.
func Serve(ctx context.Context, socketPath string, fallback Fallback, in io.Reader, out io.Writer) error {
	return ServeWith(ctx, socketPath, fallback, in, out, Options{})
}

// Options tune Serve.
type Options struct {
	// ReconnectWait is how long a message waits for an engine that was
	// serving this session and went away; zero means DefaultReconnectWait,
	// negative means do not wait.
	ReconnectWait time.Duration

	// MinEngineProtocol is the oldest engine protocol this shim works with
	// (default mcpserver.MinEngineProtocol); an older engine is refused with the
	// message that names the restart.
	MinEngineProtocol int

	// Start, when set, is called when a message finds no engine and the
	// engine was not up a moment ago; it returns once it started one (or
	// found one starting) or failed. The shim then waits up to StartWait
	// for the socket before answering from the fallback. After an error the
	// shim tries the socket once and does not wait.
	Start func(ctx context.Context) error
	// StartWait is how long to wait for the socket after Start; zero means
	// DefaultStartWait.
	StartWait time.Duration

	// Open, when set, opens a link in the person's browser. The shim calls
	// it for the links of the engine's answers that point to the engine's
	// own local pages, when the engine said in its hello answer that a
	// person operates it (CONTRACT.md, Auto-open). Nil opens nothing.
	Open func(ctx context.Context, link string) error

	// UploadPlugin, when set, reads and uploads the plugin folder a
	// request_plugin call names (CONTRACT.md, MCP tools, request_plugin).
	// Nil uploads nothing, and the engine refuses such a call.
	UploadPlugin PluginUploader
	// UploadAllowed, given who the engine's hello answer says operates it
	// and its local page origin, says whether UploadPlugin runs for it
	// (plugin.UploadAllowed). Nil uploads nothing.
	UploadAllowed func(operatedBy, pagesOrigin string) bool
}

// ServeWith is Serve with options.
func ServeWith(ctx context.Context, socketPath string, fallback Fallback, in io.Reader, out io.Writer, opts Options) error {
	if fallback == nil {
		panic("shim: fallback server required")
	}
	wait := opts.ReconnectWait
	if wait == 0 {
		wait = DefaultReconnectWait
	}
	startWait := opts.StartWait
	if startWait == 0 {
		startWait = DefaultStartWait
	}
	minEngine := opts.MinEngineProtocol
	if minEngine == 0 {
		minEngine = mcpserver.MinEngineProtocol
	}
	r := &relay{
		neg:  negotiation{build: buildinfo.Version, minEngine: minEngine},
		path: socketPath, fallback: fallback, out: &lineWriter{w: out}, files: defaultRequestFiles(), dial: dial,
		reconnectWait: wait, start: opts.Start, startWait: startWait, retries: make(chan []byte, retryQueue), retried: map[string]bool{},
		opener: newAutoOpener(opts.Open), upload: opts.UploadPlugin, uploadAllowed: opts.UploadAllowed,
	}
	return serve(ctx, r, in)
}

// serve is Serve on r.
func serve(ctx context.Context, r *relay, in io.Reader) error {
	defer r.drainRetries(ctx)
	defer r.close()

	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go readLines(ctx, in, lines, readErr)
	for {
		// Requests handed back go first, so a resent call keeps its place
		// before the client's later ones.
		select {
		case line := <-r.retries:
			if err := r.send(ctx, line); err != nil {
				return err
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return nil
		case line := <-r.retries:
			if err := r.send(ctx, line); err != nil {
				return err
			}
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
// negotiation is what a session needs to agree on a protocol version with
// the engine.
type negotiation struct {
	build     string
	minEngine int
}

type relay struct {
	neg      negotiation
	path     string
	fallback Fallback
	out      *lineWriter
	sess     *session
	// files writes the request files of hash links (request_files.go).
	files requestFiles
	// dial opens a session with the engine (dial; tests wrap it).
	dial func(ctx context.Context, path string, out *lineWriter, fallback Fallback, files requestFiles, neg negotiation) (*session, error)
	// refusal is the engine's refusal of the last session that ended, ""
	// when that session was admitted or there was none.
	refusal string

	reconnectWait time.Duration
	// wasUp is set while the engine answered the last dial; only then does a
	// message wait for it to come back, so a stopped engine costs one wait.
	wasUp bool
	// start and startWait: Options.Start and Options.StartWait.
	start     func(ctx context.Context) error
	startWait time.Duration
	// opener opens the engine's local page links (Options.Open); nil when
	// there is no opener.
	opener *autoOpener
	// upload reads and uploads a request_plugin call's folder
	// (Options.UploadPlugin); nil uploads nothing.
	upload PluginUploader
	// uploadAllowed says whether upload runs for an engine
	// (Options.UploadAllowed); nil uploads nothing.
	uploadAllowed func(operatedBy, pagesOrigin string) bool

	// retries carries the in-flight reads a dying session hands back to the
	// serve loop; retried holds the ids already given their one retry.
	retries chan []byte
	mu      sync.Mutex
	retried map[string]bool
	closing bool
}

// retry takes back a request the engine never answered, once, when it is
// safe to run again; false means the caller answers it as abandoned.
func (r *relay) retry(line []byte) bool {
	if !retriable(line) {
		return false
	}
	return r.requeue(line)
}

// resend takes back a request the engine answered as not run because it
// was restarting: any request, since nothing ran, but once only; false
// means the caller passes the engine's answer on.
func (r *relay) resend(line []byte) bool { return r.requeue(line) }

// requeue hands line back to the serve loop once per request id.
func (r *relay) requeue(line []byte) bool {
	key := messageID(line)
	if key == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.retried[key] {
		return false
	}
	select {
	case r.retries <- line:
		r.retried[key] = true
		return true
	default:
		return false
	}
}

// drainRetries answers what is still queued once the serve loop stops.
func (r *relay) drainRetries(ctx context.Context) {
	r.mu.Lock()
	r.closing = true
	r.mu.Unlock()
	for {
		select {
		case line := <-r.retries:
			_ = r.fallback.Abandoned(context.WithoutCancel(ctx), r.out, line)
		default:
			return
		}
	}
}

// dialWaiting dials, and when the engine was up until now keeps trying for
// reconnectWait: the engine is restarting, not gone. When it never comes
// back, or was not up, and there is a starter, it starts one.
func (r *relay) dialWaiting(ctx context.Context) (*session, error) {
	sess, err := r.dial(ctx, r.path, r.out, r.fallback, r.files, r.neg)
	if err == nil {
		return r.up(sess), nil
	}
	if r.start == nil {
		if !r.wasUp || r.reconnectWait <= 0 {
			return nil, err
		}
		return r.waitFor(ctx, r.reconnectWait, err)
	}
	if r.wasUp && r.reconnectWait > 0 {
		if sess, err = r.waitFor(ctx, r.reconnectWait, err); sess != nil || ctx.Err() != nil {
			return sess, err
		}
	}
	r.wasUp = false
	return r.startEngine(ctx, err)
}

// up marks the engine as up and gives sess the relay's retry hooks.
func (r *relay) up(sess *session) *session {
	sess.retry, sess.resend = r.retry, r.resend
	sess.opener.Store(r.opener)
	r.wasUp = true
	return sess
}

// waitFor dials every reconnectPoll until wait passes; it returns the
// session, or nil with the last dial error (wasUp is then false).
func (r *relay) waitFor(ctx context.Context, wait time.Duration, err error) (*session, error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(reconnectPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, err
		case <-deadline.C:
			r.wasUp = false
			return nil, err
		case <-tick.C:
			sess, derr := r.dial(ctx, r.path, r.out, r.fallback, r.files, r.neg)
			if derr == nil {
				return r.up(sess), nil
			}
			err = derr
		}
	}
}

// startEngine calls the starter, then waits up to startWait for the socket
// from the call (one try when the starter failed).
func (r *relay) startEngine(ctx context.Context, err error) (*session, error) {
	began := time.Now()
	serr := r.start(ctx)
	// The engine may already answer, and a short wait would end before the
	// first poll.
	sess, derr := r.dial(ctx, r.path, r.out, r.fallback, r.files, r.neg)
	if derr == nil {
		return r.up(sess), nil
	}
	if serr != nil {
		return nil, err
	}
	// The starter's own wait counts: a message never waits longer than
	// startWait in all.
	return r.waitFor(ctx, max(r.startWait-time.Since(began), 0), derr)
}

// send forwards line to the engine, dialing when there is no live
// connection, or answers it from the fallback when the engine does not take
// it. A connection the engine refused before it could take line (its
// refusal and close came first) answers line with that refusal.
func (r *relay) send(ctx context.Context, line []byte) error {
	if r.sess != nil {
		prepared, answered := r.prepare(ctx, r.sess, line)
		if answered || r.sess.forward(prepared) {
			return nil
		}
	}
	r.close()
	sess, err := r.dialWaiting(ctx)
	if err == nil {
		r.sess = sess
		prepared, answered := r.prepare(ctx, sess, line)
		if answered || sess.forward(prepared) {
			return nil
		}
		r.close()
		if r.refusal != "" {
			return refuse(r.out, line, r.refusal)
		}
	}
	return r.fallback.ServeLine(ctx, r.out, line)
}

// finish closes the write side of a live connection and waits for the
// engine's last answers. With no live connection it reports the refusal of
// the last one, if the engine refused it.
func (r *relay) finish(ctx context.Context) error {
	defer r.drainRetries(ctx)
	if r.sess == nil && r.refusal != "" {
		return errors.New(r.refusal)
	}
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

// restartingClose is how long a session whose engine said it is
// restarting is still read before it is closed: the engine ends it soon
// after its last answer, and the answers still coming are its other
// "not run" answers.
const restartingClose = time.Second

func (r *relay) close() {
	if r.sess == nil {
		return
	}
	if r.sess.isRestarting() {
		t := time.NewTimer(restartingClose)
		select {
		case <-r.sess.done:
		case <-t.C:
		}
		t.Stop()
	}
	r.sess.conn.Close()
	<-r.sess.done
	r.refusal = r.sess.refusal // read only once the session is done
	r.sess = nil
}

// session is one connection to the engine and the goroutine copying its
// answers to the client. It keeps the requests the engine has not answered
// yet, by id, and answers them through the fallback when the connection
// ends.
type session struct {
	conn      *net.UnixConn
	fallback  Fallback
	files     requestFiles
	neg       negotiation
	done      chan struct{}
	ready     chan struct{} // closed once the hello is answered or the session ends
	readyOnce sync.Once
	// err is the read error that ended the session, set before done closes;
	// nil for a clean close.
	err error

	// refusal is the engine's refusal of this OS user (mcpserver.PeerRefusal),
	// "" when it admitted the peer.
	refusal string
	// retry takes back an unanswered request that is safe to run again.
	retry func(line []byte) bool
	// resend takes back a request the engine did not run because it is
	// restarting.
	resend func(line []byte) bool
	// beforeWrite, when set (tests), runs once a request is pending and
	// before it is written.
	beforeWrite func()
	// engine is the engine's hello answer, read only by copyAnswers;
	// opener opens the links of its answers (relay.opener).
	engine mcpserver.Hello
	opener atomic.Pointer[autoOpener]

	// wmu is held by forward from recording a request as pending until its
	// write returns, and by abandon while it takes the pending requests.
	wmu   sync.Mutex
	mu    sync.Mutex
	ended bool
	// restarting is set once the engine answered a request as not run
	// because it is restarting: nothing more is sent on this session.
	restarting bool
	pending    map[string][]byte
}

func dial(ctx context.Context, path string, out *lineWriter, fallback Fallback, files requestFiles, neg negotiation) (*session, error) {
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
	s := &session{conn: conn, fallback: fallback, files: files, neg: neg, done: make(chan struct{}), ready: make(chan struct{}), pending: map[string][]byte{}}
	// The first line on every connection: the shim's protocol version. A
	// write that fails (a refused peer) shows up as the connection ending.
	_, _ = conn.Write(mcpserver.HelloLine(neg.build))
	go s.copyAnswers(ctx, out)
	return s, nil
}

// copyAnswers writes each line the engine sends to out until the engine
// closes the connection, then answers what it left unanswered.
func (s *session) copyAnswers(ctx context.Context, out *lineWriter) {
	defer close(s.done)
	defer s.markReady()
	defer s.abandon(ctx, out)
	sc := bufio.NewScanner(s.conn)
	sc.Buffer(make([]byte, scannerInitSize), scannerMaxSize)
	for sc.Scan() {
		if msg := mcpserver.PeerRefusal(sc.Bytes()); msg != "" {
			// Not a request's answer: the requests left pending get its
			// message when the engine closes.
			s.refusal = msg
			continue
		}
		if hello, known, ok := mcpserver.HelloAnswer(sc.Bytes()); ok {
			if known {
				s.engine = hello
			}
			if known && s.engineTooOld(hello) {
				// Not ready yet: the deferred abandon marks the session ended
				// first, then releases forward, which then finds it ended.
				s.conn.Close()
				return
			}
			s.markReady()
			continue
		}
		if s.takeBackRestarting(sc.Bytes()) {
			continue
		}
		s.answered(sc.Bytes())
		if err := out.writeLine(s.files.attach(sc.Bytes())); err != nil {
			s.err = fmt.Errorf("write to the MCP client: %w", err)
			return
		}
		s.opener.Load().answer(ctx, s.engine, sc.Bytes())
	}
	if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.err = fmt.Errorf("relay from engine: %w", err)
	}
	if s.refusal != "" {
		s.err = errors.New(s.refusal)
	}
}

// abandon ends the session and answers every request still pending.
// engineTooOld records the refusal for an engine that is older than this
// shim works with; the pending requests and every later one are answered
// with it.
func (s *session) engineTooOld(engine mcpserver.Hello) bool {
	if engine.Protocol >= s.neg.minEngine {
		return false
	}
	me := mcpserver.Hello{Protocol: mcpserver.ShimProtocol, Build: s.neg.build}
	s.refusal = mcpserver.EngineTooOldMessage(me, engine, s.neg.minEngine)
	return true
}

func (s *session) abandon(ctx context.Context, out *lineWriter) {
	// A write still in progress settles first whether its request reached
	// the engine. It ends soon: the engine has closed its side, and a socket
	// the peer closed fails the write.
	s.wmu.Lock()
	s.mu.Lock()
	s.ended = true
	left := s.pending
	s.pending = nil
	s.mu.Unlock()
	s.wmu.Unlock()
	for _, line := range left {
		if s.refusal != "" {
			_ = refuse(out, line, s.refusal)
			continue
		}
		if s.retry != nil && s.retry(line) {
			continue
		}
		_ = s.fallback.Abandoned(context.WithoutCancel(ctx), out, line)
	}
}

// refuse answers a request with the engine's refusal of this OS user; any
// other message gets no answer.
func refuse(out io.Writer, line []byte, refusal string) error {
	req, ok := mcpserver.RequestOf(line)
	if !ok {
		return nil
	}
	return mcpserver.WriteError(out, req.ID, mcpserver.ErrCodeServer, refusal)
}

func (s *session) markReady() { s.readyOnce.Do(func() { close(s.ready) }) }

// helloWait is how long the first request waits for the engine's answer to
// the hello; an engine that stays silent is served as if it had answered.
const helloWait = 3 * time.Second

// forward hands line to the engine and reports whether the session took
// it: false when the session has ended or the write failed, and the caller
// answers it some other way.
func (s *session) forward(line []byte) bool {
	// No request reaches the engine before its version is known, so an
	// engine that is too old never runs one.
	select {
	case <-s.ready:
	default:
		t := time.NewTimer(helloWait)
		select {
		case <-s.ready:
		case <-t.C:
		}
		t.Stop()
	}
	// abandon waits for this write: a request whose write failed never
	// reached the engine, so it is not answered as dropped but taken back
	// here, for the caller to send to the engine that comes back.
	s.wmu.Lock()
	defer s.wmu.Unlock()
	key := messageID(line)
	s.mu.Lock()
	if s.ended || s.restarting {
		s.mu.Unlock()
		return false
	}
	if key != "" {
		s.pending[key] = line
	}
	s.mu.Unlock()
	if s.beforeWrite != nil {
		s.beforeWrite()
	}
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

// takeBackRestarting hands the request of an answer that says the engine
// is restarting and did not run it back to the relay, to be sent to the
// engine that comes back; false when line is another answer, or the
// request was already sent once more (the answer is then passed on).
func (s *session) takeBackRestarting(line []byte) bool {
	key, ok := mcpserver.Restarting(line)
	if !ok {
		return false
	}
	s.mu.Lock()
	s.restarting = true
	req, pending := s.pending[key]
	delete(s.pending, key)
	s.mu.Unlock()
	return pending && s.resend != nil && s.resend(req)
}

func (s *session) isRestarting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restarting
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
