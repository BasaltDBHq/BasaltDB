// Package mcp is a minimal Model Context Protocol server: newline-delimited
// JSON-RPC 2.0 over any byte stream (stdio for a local agent, or a Unix
// socket connection between the MCP shim and the engine). It serves the
// initialize, ping, tools/list and tools/call methods for the tools it is
// given. The tool set itself is defined by the engine (CONTRACT.md).
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/resultsize"
)

const defaultProtocolVersion = "2025-03-26"

// JSON-RPC 2.0 error codes.
const (
	rpcErrParse          = -32700
	rpcErrMethodNotFound = -32601
	rpcErrInvalidParams  = -32602
)

const (
	scannerInitSize = 64 * 1024
	scannerMaxSize  = 16 << 20
)

// Tool is one MCP tool: its listing and its handler. InputSchema is the JSON
// Schema of the arguments. Call returns a value rendered as JSON text, or an
// error; a *ToolError keeps its code on the wire.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Call        func(ctx context.Context, args json.RawMessage) (any, error)
}

// Info names the server in the initialize result.
type Info struct {
	Name         string
	Version      string
	Instructions string
	// Notice, optional, is a short text for the agent to relay (an update
	// notice); "" when there is none. A connection's first successful tool
	// result carries it as an extra text item.
	Notice func() string
}

// session is the state of one Serve connection.
type session struct{ noticed bool }

// Server serves a fixed set of tools.
type Server struct {
	info   Info
	tools  []Tool
	byName map[string]Tool

	minShim int
}

// WithMinShimProtocol sets the oldest shim protocol Serve accepts; the
// default is MinShimProtocol. A connection whose shim is older gets every
// request answered with ErrCodeVersionMismatch.
func (s *Server) WithMinShimProtocol(n int) *Server {
	s.minShim = n
	return s
}

// NewServer returns a server for tools. It panics on a duplicate or unnamed
// tool, or a tool without a handler.
func NewServer(info Info, tools ...Tool) *Server {
	byName := make(map[string]Tool, len(tools))
	for _, t := range tools {
		if t.Name == "" || t.Call == nil {
			panic("mcp: tool needs a name and a handler")
		}
		if _, dup := byName[t.Name]; dup {
			panic("mcp: duplicate tool " + t.Name)
		}
		byName[t.Name] = t
	}
	return &Server{info: info, tools: tools, byName: byName, minShim: MinShimProtocol}
}

// Request is a JSON-RPC 2.0 request or notification (no id).
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads one JSON-RPC message per line from in and writes one response
// per request to out, until in ends or ctx is done. Notifications get no
// response. Callers must keep logs off out.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	return s.ServeGated(ctx, in, out, openGate{})
}

// ServeGated is Serve with every request admitted by gate: a request gate
// refuses is answered with ErrCodeRestarting and not run. The hello and
// notifications are not gated.
func (s *Server) ServeGated(ctx context.Context, in io.Reader, out io.Writer, gate Gate) error {
	sess := &session{}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, scannerInitSize), scannerMaxSize)
	shim := Hello{} // a shim that never says hello is version 0
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if handled, err := s.negotiate(out, line, &shim); handled {
			if err != nil {
				return err
			}
			continue
		}
		if err := s.serveGated(ctx, out, line, gate, sess); err != nil {
			return err
		}
	}
	return sc.Err()
}

// serveGated answers line when gate admits it, and refuses it otherwise.
func (s *Server) serveGated(ctx context.Context, out io.Writer, line []byte, gate Gate, sess *session) error {
	req, ok := RequestOf(line)
	if !ok {
		return s.serveLine(ctx, out, line, sess)
	}
	if !gate.Begin() {
		return WriteError(out, req.ID, ErrCodeRestarting, RestartingMessage)
	}
	defer gate.End()
	return s.serveLine(ctx, out, line, sess)
}

// negotiate answers the hello request, and refuses every other request
// while the connection's shim is older than the engine serves. handled is
// true when line is done.
func (s *Server) negotiate(out io.Writer, line []byte, shim *Hello) (handled bool, err error) {
	req, ok := RequestOf(line)
	if !ok {
		return false, nil
	}
	engine := Hello{Protocol: ShimProtocol, Build: s.info.Version, MinShimProtocol: &s.minShim}
	if req.Method == HelloMethod {
		_ = json.Unmarshal(req.Params, shim) // malformed: stays version 0
		if shim.Protocol < s.minShim {
			return true, WriteError(out, req.ID, ErrCodeVersionMismatch, ShimTooOldMessage(*shim, engine, s.minShim))
		}
		return true, writeResponse(out, req.ID, engine, nil)
	}
	if shim.Protocol < s.minShim {
		return true, WriteError(out, req.ID, ErrCodeVersionMismatch, ShimTooOldMessage(*shim, engine, s.minShim))
	}
	return false, nil
}

// ServeLine answers one JSON-RPC message on out, as Serve does for each line
// (the MCP shim answers the lines the engine cannot).
func (s *Server) ServeLine(ctx context.Context, out io.Writer, line []byte) error {
	return s.serveLine(ctx, out, bytes.TrimSpace(line), nil)
}

func (s *Server) serveLine(ctx context.Context, out io.Writer, line []byte, sess *session) error {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return writeResponse(out, nil, nil, &RPCError{Code: rpcErrParse, Message: "parse error"})
	}
	if req.ID == nil {
		return nil
	}
	result, rpcErr := s.handle(ctx, req.Method, req.Params, sess)
	return writeResponse(out, req.ID, result, rpcErr)
}

func (s *Server) handle(ctx context.Context, method string, params json.RawMessage, sess *session) (any, *RPCError) {
	switch method {
	case "initialize":
		return s.initialize(params), nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.listTools()}, nil
	case "tools/call":
		return s.callTool(ctx, params, sess)
	default:
		return nil, &RPCError{Code: rpcErrMethodNotFound, Message: "method not found: " + method}
	}
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	// A malformed initialize falls back to the default protocol version.
	_ = json.Unmarshal(params, &p)
	version := p.ProtocolVersion
	if version == "" {
		version = defaultProtocolVersion
	}
	out := map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]string{"name": s.info.Name, "version": s.info.Version},
	}
	if s.info.Instructions != "" {
		out["instructions"] = s.info.Instructions
	}
	return out
}

func (s *Server) listTools() []map[string]any {
	out := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		out = append(out, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": schema})
	}
	return out
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage, sess *session) (any, *RPCError) {
	var req struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("invalid params: %v", err)}
	}
	tool, ok := s.byName[req.Name]
	if !ok {
		return nil, &RPCError{Code: rpcErrMethodNotFound, Message: "unknown tool: " + req.Name}
	}
	if len(req.Arguments) == 0 {
		req.Arguments = json.RawMessage(`{}`)
	}
	// One result budget for every read the call makes (CONTRACT.md,
	// QUERY_TIMEOUT SIZE_LIMIT).
	out, err := tool.Call(resultsize.With(ctx), req.Arguments)
	if err == nil {
		res := toolResult(out, false)
		s.addNotice(res, sess)
		return res, nil
	}
	var te *ToolError
	if errors.As(err, &te) {
		return errorResult(te), nil
	}
	return toolResult(map[string]string{"message": err.Error()}, true), nil
}

// addNotice appends the server's notice to res once per connection.
func (s *Server) addNotice(res map[string]any, sess *session) {
	if s.info.Notice == nil || sess == nil || sess.noticed {
		return
	}
	text := s.info.Notice()
	if text == "" {
		return
	}
	sess.noticed = true
	content, ok := res["content"].([]map[string]any)
	if !ok {
		return // toolResult always builds this shape
	}
	res["content"] = append(content, textItem(text))
}

// errorResult is the tools/call result of te, with docsUrl set from its code
// (on a copy: te may be shared).
func errorResult(te *ToolError) map[string]any {
	out := *te
	if out.DocsURL == "" && out.Code != "" {
		out.DocsURL = DocsURL(out.Code)
	}
	return toolResult(&out, true)
}

// textItem is one text content item of a tools/call result.
func textItem(text string) map[string]any {
	return map[string]any{"type": "text", "text": text}
}

func toolResult(v any, isError bool) map[string]any {
	text, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		text = []byte(err.Error())
	}
	return map[string]any{
		"content": []map[string]any{textItem(string(text))},
		"isError": isError,
	}
}

// RequestOf decodes line as a request that wants an answer; ok is false
// for a notification or a line that is not a JSON-RPC message.
func RequestOf(line []byte) (req Request, ok bool) {
	if json.Unmarshal(line, &req) != nil {
		return Request{}, false
	}
	return req, req.ID != nil
}

// ErrCodeServer is the JSON-RPC server error code for a request the server
// could not answer (the shim, for one its engine took and dropped).
const ErrCodeServer = -32000

// ErrCodePeerRefused is the one line the engine writes, with a null id,
// before it closes a connection from an OS user other than the agent's
// (CONTRACT.md, Next steps, Startup failures). The shim answers the
// client's requests with its message.
const ErrCodePeerRefused = -32001

// WritePeerRefused writes the engine's refusal of a peer.
func WritePeerRefused(w io.Writer, message string) error {
	return WriteError(w, nil, ErrCodePeerRefused, message)
}

// PeerRefusal is the message of an engine's refusal line; "" for any other
// line.
func PeerRefusal(line []byte) string {
	var r struct {
		ID    any       `json:"id"`
		Error *RPCError `json:"error"`
	}
	if json.Unmarshal(line, &r) != nil || r.ID != nil || r.Error == nil || r.Error.Code != ErrCodePeerRefused {
		return ""
	}
	return r.Error.Message
}

// WriteToolError writes the tools/call answer for request id that carries
// te, with isError set.
func WriteToolError(w io.Writer, id any, te *ToolError) error {
	return writeResponse(w, id, errorResult(te), nil)
}

// WriteError writes a JSON-RPC error answer for request id.
func WriteError(w io.Writer, id any, code int, message string) error {
	return writeResponse(w, id, nil, &RPCError{Code: code, Message: message})
}

func writeResponse(w io.Writer, id, result any, rpcErr *RPCError) error {
	return json.NewEncoder(w).Encode(Response{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr})
}
