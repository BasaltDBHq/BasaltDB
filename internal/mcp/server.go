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
}

// Server serves a fixed set of tools.
type Server struct {
	info   Info
	tools  []Tool
	byName map[string]Tool
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
	return &Server{info: info, tools: tools, byName: byName}
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
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, scannerInitSize), scannerMaxSize)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := s.serveLine(ctx, out, line); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ServeLine answers one JSON-RPC message on out, as Serve does for each line
// (the MCP shim answers the lines the engine cannot).
func (s *Server) ServeLine(ctx context.Context, out io.Writer, line []byte) error {
	return s.serveLine(ctx, out, bytes.TrimSpace(line))
}

func (s *Server) serveLine(ctx context.Context, out io.Writer, line []byte) error {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return writeResponse(out, nil, nil, &RPCError{Code: rpcErrParse, Message: "parse error"})
	}
	if req.ID == nil {
		return nil
	}
	result, rpcErr := s.handle(ctx, req.Method, req.Params)
	return writeResponse(out, req.ID, result, rpcErr)
}

func (s *Server) handle(ctx context.Context, method string, params json.RawMessage) (any, *RPCError) {
	switch method {
	case "initialize":
		return s.initialize(params), nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.listTools()}, nil
	case "tools/call":
		return s.callTool(ctx, params)
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

func (s *Server) callTool(ctx context.Context, params json.RawMessage) (any, *RPCError) {
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
	out, err := tool.Call(ctx, req.Arguments)
	if err == nil {
		return toolResult(out, false), nil
	}
	var te *ToolError
	if errors.As(err, &te) {
		return toolResult(te, true), nil
	}
	return toolResult(map[string]string{"message": err.Error()}, true), nil
}

func toolResult(v any, isError bool) map[string]any {
	text, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		text = []byte(err.Error())
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}},
		"isError": isError,
	}
}

func writeResponse(w io.Writer, id, result any, rpcErr *RPCError) error {
	return json.NewEncoder(w).Encode(Response{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr})
}
