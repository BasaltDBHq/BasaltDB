package sdk

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

const (
	jsonrpcVersion = "2.0"
	// readBufferBytes is the size of the buffered reader; a longer line is
	// assembled from several reads, never beyond the message cap.
	readBufferBytes = 64 << 10
	// closeWait bounds the wait for a reader that closing its stream did not
	// unblock (a terminal, for instance).
	closeWait = 500 * time.Millisecond
)

var errTooLong = errors.New("sdk: line over the size cap")

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcBody        `json:"error,omitempty"`
}

// serveConn serves one JSON-RPC connection until the reader ends, the stream
// breaks, or ctx ends. It closes rc. It returns ErrMessageTooLarge when the
// peer sent a line over the cap, nil in every other case.
//
// Calls are served concurrently, at most MaxInFlight at a time: the reader
// waits for a free slot, so a flood of requests cannot start unbounded work.
// Replies may arrive out of order; each carries its request's id.
func (s *server) serveConn(ctx context.Context, rc io.ReadCloser, w io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c := &jsonrpcConn{s: s, w: w, slots: make(chan struct{}, protocol.MaxInFlight)}
	readDone := make(chan error, 1)
	go func() { readDone <- c.readLoop(ctx, rc) }()

	var err error
	select {
	case err = <-readDone:
		// The peer closed its side. Calls already running finish and are
		// answered, bounded by the call timeout; a cancelled parent ctx or a
		// stuck handler ends the wait.
		drain := time.NewTimer(time.Duration(s.timeoutNs.Load()) + closeWait)
		handlers := make(chan struct{})
		go func() { c.wg.Wait(); close(handlers) }()
		select {
		case <-handlers:
		case <-ctx.Done():
		case <-drain.C:
		}
		drain.Stop()
	case <-ctx.Done():
		_ = rc.Close()
		select {
		case err = <-readDone:
		case <-time.After(closeWait):
		}
	}
	if !errors.Is(err, ErrMessageTooLarge) {
		err = nil // an ended stream is a clean end
	}
	cancel()
	_ = rc.Close()
	// Handlers see the cancelled ctx. One stuck writing to a peer that no
	// longer reads is abandoned after a moment: the process is ending.
	handlers := make(chan struct{})
	go func() { c.wg.Wait(); close(handlers) }()
	select {
	case <-handlers:
	case <-time.After(closeWait):
	}
	return err
}

type jsonrpcConn struct {
	s     *server
	w     io.Writer
	wmu   sync.Mutex
	slots chan struct{}
	wg    sync.WaitGroup
}

func (c *jsonrpcConn) readLoop(ctx context.Context, r io.Reader) error {
	br := bufio.NewReaderSize(r, readBufferBytes)
	for {
		line, err := readLine(br, protocol.MaxMessageBytes)
		if errors.Is(err, errTooLong) {
			// Refused before any of it is decoded. The rest of the line is
			// unread, so the stream cannot be trusted again.
			c.write(rpcResponse{JSONRPC: jsonrpcVersion, Error: &rpcBody{Code: codeInvalidRequest, Message: "message over the size cap"}})
			return ErrMessageTooLarge
		}
		if err != nil {
			return err // the peer closed the stream, or ctx closed it
		}
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			continue
		}
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer func() { <-c.slots }()
			c.handle(ctx, line)
		}()
	}
}

// handle answers one line.
func (c *jsonrpcConn) handle(ctx context.Context, line []byte) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		c.write(rpcResponse{JSONRPC: jsonrpcVersion, Error: &rpcBody{Code: codeParse, Message: "parse error"}})
		return
	}
	notification := len(req.ID) == 0
	id := req.ID
	if !notification && !validID(id) {
		c.write(rpcResponse{JSONRPC: jsonrpcVersion, Error: &rpcBody{Code: codeInvalidRequest, Message: "invalid request"}})
		return
	}
	if req.JSONRPC != jsonrpcVersion || req.Method == "" {
		c.reply(id, notification, nil, &rpcError{codeInvalidRequest, "invalid request"})
		return
	}
	params := req.Params
	if len(params) == 0 || bytes.Equal(params, []byte("null")) {
		params = json.RawMessage("{}")
	}
	callCtx, cancel := c.s.callContext(ctx)
	res, e := c.s.dispatch(callCtx, req.Method, params)
	cancel()
	c.reply(id, notification, res, e)
	if req.Method == protocol.MethodShutdown && e == nil {
		c.s.requestStop()
	}
}

func validID(id json.RawMessage) bool {
	return len(id) > 0 && (id[0] == '"' || id[0] == '-' || (id[0] >= '0' && id[0] <= '9'))
}

func (c *jsonrpcConn) reply(id json.RawMessage, notification bool, res any, e *rpcError) {
	if notification {
		return
	}
	out := rpcResponse{JSONRPC: jsonrpcVersion, ID: id}
	if e != nil {
		out.Error = &rpcBody{Code: e.code, Message: e.msg}
	} else {
		out.Result = res
	}
	c.write(out)
}

// write sends one response line. A result over the size cap is replaced by an
// error: the SDK never sends the engine a message it must refuse.
func (c *jsonrpcConn) write(out rpcResponse) {
	b, err := json.Marshal(out)
	if err != nil {
		out = rpcResponse{JSONRPC: jsonrpcVersion, ID: out.ID, Error: &rpcBody{Code: codeInternal, Message: errInternal.msg}}
		b, _ = json.Marshal(out) //nolint:errchkjson // an error body and an id that decoded as JSON always encode
	}
	if len(b) > protocol.MaxMessageBytes {
		out = rpcResponse{JSONRPC: jsonrpcVersion, ID: out.ID, Error: &rpcBody{Code: errTooBig.code, Message: errTooBig.msg}}
		b, _ = json.Marshal(out) //nolint:errchkjson // as above
	}
	b = append(b, '\n')
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, _ = c.w.Write(b)
}

// readLine reads one line without its newline. It fails with errTooLong as soon
// as the line is known to be longer than maxLen, so a peer cannot make the
// plugin buffer more than that.
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

// serveJSONRPCListener accepts connections until ctx ends. Each connection is
// served on its own; the plugin's state is shared between them.
func (s *server) serveJSONRPCListener(ctx context.Context, l net.Listener) error {
	// A failed accept cancels this context before the wait below, so the
	// connections still open end instead of holding Serve up.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	go func() {
		<-connCtx.Done()
		_ = l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			stopping := ctx.Err() != nil
			cancel()
			wg.Wait()
			if stopping {
				return nil // the accept failed because Serve is stopping
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A connection that sent an oversized line is closed; the plugin
			// goes on serving the others.
			_ = s.serveConn(connCtx, c, c)
		}()
	}
}
