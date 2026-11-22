// Package jsonrpc is the JSON-RPC 2.0 adapter for plugins: newline-delimited
// messages over a child process's stdin and stdout (Spawn) or over a Unix
// socket the plugin listens on (Dial). Both give a plugin.Transport.
//
// A message is one line. A line longer than protocol.MaxMessageBytes is
// refused while it is read, before any of it is decoded. No payload value is
// ever written to a log or put in an error: a failed call carries a failure
// class and nothing else.
package jsonrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"

	protocol "github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	plugin "github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

const (
	version = "2.0"
	// readBufferBytes is the size of the buffered reader; a longer line is
	// assembled from several reads, never beyond the message cap.
	readBufferBytes = 64 << 10
)

var errTooLong = errors.New("jsonrpc: message over the size cap")

// reply is what the reader hands to the call waiting for an id.
type reply struct {
	result json.RawMessage
	err    error
}

// frame is one request line queued for the writer.
type frame struct {
	ctx  context.Context
	line []byte
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  *string         `json:"method"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// conn is one connection to one plugin. It owns a reader and a writer
// goroutine; it shares nothing with any other conn.
type conn struct {
	w       io.Writer
	stop    func() // idempotent: closes the pipes or socket and stops the process
	writeCh chan frame
	done    chan struct{} // closed when the connection is dead
	wg      sync.WaitGroup

	mu        sync.Mutex
	nextID    uint64
	pending   map[uint64]chan reply
	dead      bool
	deadClass plugin.FailureClass
}

// newConn starts the reader and the writer. stop must be safe to call more
// than once and from any goroutine, and must make a blocked read or write
// return.
func newConn(r io.Reader, w io.Writer, stop func()) *conn {
	c := &conn{
		w:       w,
		stop:    stop,
		writeCh: make(chan frame),
		done:    make(chan struct{}),
		pending: map[uint64]chan reply{},
	}
	c.wg.Add(2)
	go c.readLoop(bufio.NewReaderSize(r, readBufferBytes))
	go c.writeLoop()
	return c
}

// Call sends one request and waits for its response. It returns promptly when
// ctx ends, with ctx's own error; the host maps that to TIMEOUT or hands it
// back to the caller.
func (c *conn) Call(ctx context.Context, method string, params, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := marshalParams(params)
	if err != nil {
		return err
	}

	id, ch, err := c.register()
	if err != nil {
		return err
	}
	defer c.forget(id)

	line, err := protocol.Marshal(request{JSONRPC: version, ID: id, Method: method, Params: body})
	if err != nil {
		return plugin.Fail(plugin.ClassBadResponse)
	}
	if len(line) > protocol.MaxMessageBytes {
		return plugin.Fail(plugin.ClassOverLimit)
	}

	select {
	case c.writeCh <- frame{ctx: ctx, line: append(line, '\n')}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		// The failure is already in ch.
	}

	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		return decodeResult(r.result, result)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops the connection and everything it started, and waits for its
// goroutines. It is safe to call more than once.
func (c *conn) Close() error {
	c.fail(plugin.ClassUnavailable)
	c.stop()
	c.wg.Wait()
	return nil
}

func marshalParams(params any) (json.RawMessage, error) {
	if params == nil {
		return nil, nil
	}
	b, err := protocol.Marshal(params)
	if err != nil {
		return nil, err
	}
	if len(b) > protocol.MaxMessageBytes {
		return nil, plugin.Fail(plugin.ClassOverLimit)
	}
	return b, nil
}

func decodeResult(raw json.RawMessage, result any) error {
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return plugin.Fail(plugin.ClassBadResponse)
	}
	return nil
}

func (c *conn) register() (uint64, chan reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return 0, nil, plugin.Fail(c.laterClass())
	}
	c.nextID++
	ch := make(chan reply, 1)
	c.pending[c.nextID] = ch
	return c.nextID, ch, nil
}

func (c *conn) forget(id uint64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// laterClass is the class a call gets once the connection is dead: a plugin
// that went away stays EXITED; any other end is UNAVAILABLE. Callers hold mu.
func (c *conn) laterClass() plugin.FailureClass {
	if c.deadClass == plugin.ClassExited {
		return plugin.ClassExited
	}
	return plugin.ClassUnavailable
}

// fail marks the connection dead once. Calls waiting now get class; later
// calls get laterClass. It does not stop the process or the socket.
func (c *conn) fail(class plugin.FailureClass) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return
	}
	c.dead = true
	c.deadClass = class
	for id, ch := range c.pending {
		ch <- reply{err: plugin.Fail(class)} // buffered, one slot, never sent twice
		delete(c.pending, id)
	}
	close(c.done)
}

// abort ends the connection after a failure the reader or writer saw.
func (c *conn) abort(class plugin.FailureClass) {
	c.fail(class)
	c.stop()
}

func (c *conn) writeLoop() {
	defer c.wg.Done()
	for {
		select {
		case f := <-c.writeCh:
			if f.ctx.Err() != nil {
				continue // the caller gave up before the write; send nothing
			}
			if _, err := c.w.Write(f.line); err != nil {
				c.abort(plugin.ClassExited)
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *conn) readLoop(br *bufio.Reader) {
	defer c.wg.Done()
	for {
		line, err := readLine(br, protocol.MaxMessageBytes)
		if errors.Is(err, errTooLong) {
			c.abort(plugin.ClassBadResponse)
			return
		}
		if err != nil {
			c.abort(plugin.ClassExited)
			return
		}
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			continue
		}
		if !c.dispatch(line) {
			c.abort(plugin.ClassBadResponse)
			return
		}
	}
}

// dispatch hands one response to its call. It reports false when the line is
// not a response this connection can account for.
func (c *conn) dispatch(line []byte) bool {
	var m response
	if err := json.Unmarshal(line, &m); err != nil {
		return false
	}
	if m.JSONRPC != version || m.Method != nil {
		return false
	}
	id, err := strconv.ParseUint(string(m.ID), 10, 64)
	if err != nil {
		return false
	}

	c.mu.Lock()
	ch, ok := c.pending[id]
	issued := id >= 1 && id <= c.nextID
	delete(c.pending, id)
	c.mu.Unlock()

	if !ok {
		// A call that gave up has forgotten its id; its late answer is
		// dropped. An id this side never issued is not a response.
		return issued
	}
	ch <- classify(m)
	return true
}

// classify turns a response into what the call sees. A JSON-RPC error from
// the plugin is a failed call; its message is never read or kept.
func classify(m response) reply {
	hasResult := len(m.Result) > 0
	hasError := len(m.Error) > 0 && !bytes.Equal(m.Error, []byte("null"))
	if hasError || !hasResult {
		return reply{err: plugin.Fail(plugin.ClassBadResponse)}
	}
	return reply{result: m.Result}
}

// readLine reads one line without its newline. It fails with errTooLong as
// soon as the line is known to be longer than max, so a plugin cannot make
// the engine buffer more than max bytes.
func readLine(br *bufio.Reader, maxLen int) ([]byte, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		limit := maxLen
		if err == nil {
			limit = maxLen + 1 // the newline
		}
		if len(buf)+len(frag) > limit {
			return nil, errTooLong
		}
		buf = append(buf, frag...)
		switch {
		case err == nil:
			return buf[:len(buf)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}
