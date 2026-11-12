package person

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// PeerUIDFunc reads the OS user on the other end of a connection
// (peercred.UID outside tests).
type PeerUIDFunc func(*net.UnixConn) (uint32, error)

// Options configure a Server.
type Options struct {
	// Allow are the person uids recorded at basalt init. Root and the
	// engine's own uid are dropped; empty admits nobody.
	Allow []uint32
	// Agents are the engine's agents by name, each with its Ledger on the
	// agent's own credential.
	Agents map[string]Ledger
	// AgentUIDs are the uids of the agents' OS users (osUser), by agent
	// name. A peer that is an agent's OS user is scoped to its own agents
	// (owner decision SM-4).
	AgentUIDs map[string]uint32
	// Info answers STATUS and TARGET, by agent name; Engine is what STATUS
	// says about the engine itself.
	Info   map[string]AgentInfo
	Engine EngineInfo
	// Pages is PAGES's answer.
	Pages   PagesDTO
	PeerUID PeerUIDFunc
	Log     *slog.Logger
}

// Server serves the person socket.
type Server struct {
	allow  map[uint32]bool
	agents map[string]Ledger
	// scopes are, per agent OS user uid, the agents that uid runs.
	scopes  map[uint32]map[string]bool
	info    map[string]AgentInfo
	engine  EngineInfo
	pages   PagesDTO
	peerUID PeerUIDFunc
	log     *slog.Logger
}

// rootUID is the superuser, never a person.
const rootUID = 0

// NewServer builds a Server. It drops root and the engine's own uid from
// the allowlist, logging each.
func NewServer(o Options) *Server {
	if o.PeerUID == nil || o.Log == nil {
		panic("person: peer uid reader and logger required")
	}
	self := uint32(os.Getuid())
	allow := make(map[uint32]bool, len(o.Allow))
	for _, uid := range o.Allow {
		if uid == rootUID || uid == self {
			o.Log.Warn("person socket: ignoring a person uid that is root or the engine's own user", "uid", uid)
			continue
		}
		allow[uid] = true
	}
	if len(allow) == 0 {
		o.Log.Warn("person socket: no person uid recorded; it admits nobody (run basalt init with --person-uid)")
	}
	scopes := map[uint32]map[string]bool{}
	for name, uid := range o.AgentUIDs {
		if scopes[uid] == nil {
			scopes[uid] = map[string]bool{}
		}
		scopes[uid][name] = true
	}
	return &Server{
		allow: allow, agents: o.Agents, scopes: scopes, info: o.Info, engine: o.Engine,
		pages: o.Pages, peerUID: o.PeerUID, log: o.Log,
	}
}

// Serve accepts on ln until ctx is done, at most MaxConns at a time.
func (s *Server) Serve(ctx context.Context, ln *net.UnixListener) {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	slots := make(chan struct{}, MaxConns)
	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.log.Error("person socket: accept", "err", err)
			}
			return
		}
		conns.Go(func() {
			defer func() { <-slots }()
			s.ServeConn(ctx, conn)
		})
	}
}

// ServeConn answers one connection: the peer check before reading, the
// greeting, one request and its response.
func (s *Server) ServeConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(RequestTimeout))
	uid, err := s.peerUID(conn)
	if err != nil {
		s.log.Warn("person socket: refused a connection without peer credentials", "err", err)
		return
	}
	if !s.allow[uid] {
		s.log.Warn("person socket: refused an OS user not in personUids", "peerUid", uid)
		writeLine(conn, Greeting{Version: ProtocolVersion, Error: &Error{
			Code:    CodeUIDNotAllowed,
			Message: fmt.Sprintf("OS user %d is not a person this engine admits", uid),
		}})
		return
	}
	writeLine(conn, Greeting{OK: true, Version: ProtocolVersion})
	req, rerr := readRequest(conn)
	resp := Response{Error: rerr}
	if rerr == nil {
		resp = s.handle(ctx, uid, req)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	writeLine(conn, resp)
}

func writeLine(w io.Writer, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return // our own types always marshal
	}
	_, _ = w.Write(append(raw, '\n'))
}

// readRequest reads one request line of at most MaxRequestBytes and
// decodes it, refusing unknown keys.
func readRequest(r io.Reader) (Request, *Error) {
	line, err := bufio.NewReader(io.LimitReader(r, MaxRequestBytes+1)).ReadBytes('\n')
	switch {
	case len(line) > MaxRequestBytes:
		return Request{}, invalid(fmt.Errorf("request is larger than %d bytes", MaxRequestBytes))
	case err != nil:
		return Request{}, invalid(errors.New("no complete request line"))
	}
	var req Request
	if err := decodeStrict(line, &req); err != nil {
		return Request{}, invalid(err)
	}
	return req, nil
}

func decodeStrict(raw []byte, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func invalid(err error) *Error {
	return &Error{Code: CodeInvalidArgument, Message: err.Error()}
}

// handle runs one request against the named agent's ledger.
func (s *Server) handle(ctx context.Context, uid uint32, req Request) Response {
	if req.Method == MethodPages {
		if err := decodeStrict(req.Params, &emptyParams{}); err != nil {
			return Response{Error: invalid(err)}
		}
		return result(s.pages, nil)
	}
	h, ok := handlers[req.Method]
	if !ok {
		return Response{Error: &Error{Code: CodeUnknownMethod, Message: fmt.Sprintf("unknown method %q", req.Method)}}
	}
	if scope, isAgent := s.scopes[uid]; isAgent && !scope[req.Agent] {
		// The peer is an agent's OS user (it shares the person's uid): it
		// sees only its own agents, never another agent's ledger (SM-4).
		s.log.Warn("person socket: refused another agent's ledger to an agent's OS user", "agent", req.Agent, "peerUid", uid)
		return Response{Error: &Error{Code: CodeAgentNotAllowed, Message: fmt.Sprintf(
			"OS user %d runs an agent, so this socket serves it only that agent's ledger, not %q; "+
				"run the agent as another OS user (basalt init --os-user) to see every agent", uid, req.Agent)}}
	}
	if h == nil {
		return s.answerInfo(ctx, req)
	}
	l, ok := s.agents[req.Agent]
	if !ok {
		return Response{Error: &Error{Code: CodeUnknownAgent, Message: fmt.Sprintf("the engine serves no agent %q", req.Agent)}}
	}
	ctx, cancel := context.WithTimeout(ctx, methodTimeout(req.Method))
	defer cancel()
	s.log.Info("person socket", "method", req.Method, "agent", req.Agent, "peerUid", uid)
	out, err := h(ctx, l, req.Params)
	resp := result(out, err)
	if resp.Error != nil && resp.Error.Code == CodeInternal {
		s.log.Error("person socket: call failed", "method", req.Method, "agent", req.Agent, "err", err)
	}
	return resp
}

func result(out any, err error) Response {
	if err != nil {
		return Response{Error: toError(err)}
	}
	raw, merr := json.Marshal(out)
	if merr != nil {
		return Response{Error: &Error{Code: CodeInternal, Message: "the engine could not encode the result; see the engine log"}}
	}
	return Response{Result: raw}
}

// toError maps a ledger or Postgres error to the wire. Postgres's own
// message stays (as the same-user CLI prints it); anything else is generic,
// so no connection detail leaves the engine.
func toError(err error) *Error {
	var we *Error
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &we):
		return we
	case errors.Is(err, ledger.ErrApprovalNotFound), errors.Is(err, ledger.ErrRevertNotFound):
		return &Error{Code: CodeNotFound, Message: err.Error()}
	case errors.Is(err, ledger.ErrInvalidParams):
		return &Error{Code: CodeInvalidArgument, Message: err.Error()}
	case errors.As(err, &pe):
		msg := pe.Message
		if pe.Detail != "" {
			msg += ": " + pe.Detail
		}
		return &Error{Code: CodeRefused, Message: msg}
	}
	return &Error{Code: CodeInternal, Message: "the engine could not run the call; see the engine log"}
}

// handler decodes a method's params, makes its one Ledger call and maps
// the result to its DTO.
type handler func(ctx context.Context, l Ledger, params json.RawMessage) (any, error)

// call is a handler for a method with params P.
func call[P any](f func(ctx context.Context, l Ledger, p P) (any, error)) handler {
	return func(ctx context.Context, l Ledger, raw json.RawMessage) (any, error) {
		var p P
		if err := decodeStrict(raw, &p); err != nil {
			return nil, invalid(err)
		}
		return f(ctx, l, p)
	}
}

// maxRowChangeIDs bounds ROW_CHANGES: one page of changes.
const maxRowChangeIDs = pagination.MaxLimit

var handlers = map[Method]handler{
	MethodPages: nil, // answered by the server itself, for no agent
	// Answered from the agent's AgentInfo, without the guard check.
	MethodStatus: nil,
	MethodTarget: nil,
	MethodCheckHealth: call(func(ctx context.Context, l Ledger, p healthParams) (any, error) {
		h, err := l.CheckHealth(ctx, p.toDomain())
		return healthFromDomain(h), err
	}),
	MethodListChanges: call(func(ctx context.Context, l Ledger, p changeListParams) (any, error) {
		page, err := l.ListChanges(ctx, p.toDomain())
		return mapPage(page, changeFromDomain), err
	}),
	MethodRowChanges: call(func(ctx context.Context, l Ledger, p rowChangesParams) (any, error) {
		if len(p.ChangeIDs) > maxRowChangeIDs {
			return nil, invalid(fmt.Errorf("at most %d change ids", maxRowChangeIDs))
		}
		rows, err := l.RowChanges(ctx, p.ChangeIDs)
		return rowChangesFromDomain(rows), err
	}),
	MethodListPasskeys: call(func(ctx context.Context, l Ledger, _ emptyParams) (any, error) {
		keys, err := l.ListPasskeys(ctx)
		if err != nil {
			return nil, err
		}
		out := passkeysDTO{Items: make([]passkeyDTO, 0, len(keys))}
		for _, k := range keys {
			d, err := passkeyFromDomain(k)
			if err != nil {
				return nil, err
			}
			out.Items = append(out.Items, d)
		}
		return out, nil
	}),
	MethodFindApproval: call(func(ctx context.Context, l Ledger, p approvalIDParams) (any, error) {
		a, err := l.FindApproval(ctx, p.ApprovalID)
		return approvalDTO(a), err
	}),
	MethodSubmitApproval: call(func(ctx context.Context, l Ledger, p submitApprovalParams) (any, error) {
		at, err := l.SubmitApproval(ctx, p.ApprovalID, p.Assertion.toDomain())
		return submittedDTO{ApprovedAt: at}, err
	}),
	MethodFindRevert: call(func(ctx context.Context, l Ledger, p revertIDParams) (any, error) {
		r, err := l.FindRevert(ctx, p.RevertID)
		return revertFromDomain(r), err
	}),
	MethodPreviewRevert: call(func(ctx context.Context, l Ledger, p scopeParams) (any, error) {
		if err := p.validate(); err != nil {
			return nil, invalid(err)
		}
		lines, err := l.PreviewRevert(ctx, p.toDomain())
		return previewDTO{Lines: lines}, err
	}),
	MethodPrepareRevert: call(func(ctx context.Context, l Ledger, p scopeParams) (any, error) {
		if err := p.validate(); err != nil {
			return nil, invalid(err)
		}
		prep, err := l.PrepareRevert(ctx, p.toDomain(), p.Intent)
		return preparedDTO(prep), err
	}),
	MethodApplyRevert: call(func(ctx context.Context, l Ledger, p applyRevertParams) (any, error) {
		return l.ApplyRevert(ctx, p.RevertID, p.Assertion.toDomain())
	}),
	MethodListRevertLines: call(func(ctx context.Context, l Ledger, p revertLineParams) (any, error) {
		page, err := l.ListRevertLines(ctx, p.toDomain())
		return mapPage(page, func(r ledger.RevertLine) revertLineDTO { return revertLineDTO(r) }), err
	}),
}
