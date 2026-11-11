// Package pages serves the approval and revert pages from the engine on a
// loopback listener, with a same-origin relay for them (CONTRACT.md, Local
// pages): a short link /approvals/<id> or /reverts/<id> opens the page, the
// page reads the request for that id from the engine, and after the
// person's passkey signs it posts the signature back for the engine to
// relay with the agent's credential. The relay decides nothing: Postgres
// verifies the signature.
package pages

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"sync"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/web"
)

// maxBody bounds a relayed signature (the response JSON is about 1 KiB).
const maxBody = 16 << 10

// Agent is one agent the engine serves, as the pages use it.
// agent.ErrNotThisAgent means the id is not this agent's.
type Agent interface {
	ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error)
	RelayApproval(ctx context.Context, r approval.Response) error
	RevertRequest(ctx context.Context, id uuid.UUID) (revert.Request, error)
	RelayRevert(ctx context.Context, r revert.Response) (guard.AppliedRevert, error)
}

// Server is the pages' handler. Agents are added once each is set up,
// before the listener serves.
type Server struct {
	origin string
	log    *slog.Logger
	files  fs.FS
	mu     sync.RWMutex
	agents []Agent
}

// New returns the pages for origin, the approval page's origin, which a
// relayed POST must come from.
func New(origin string, log *slog.Logger) *Server {
	return NewWithFiles(origin, log, web.Files)
}

// NewWithFiles is New serving the page files from files instead of the
// embedded ones: the working tree's web/ for page development
// (make serve-web).
func NewWithFiles(origin string, log *slog.Logger, files fs.FS) *Server {
	if origin == "" || log == nil || files == nil {
		panic("pages: origin, logger and files required")
	}
	return &Server{origin: origin, log: log, files: files}
}

// Add serves a's approvals and reverts.
func (s *Server) Add(a Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents = append(s.agents, a)
}

// Handler routes the pages, their files and the relay.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	// The pages at their RESTful paths (links; owner decisions, Decided
	// Nov 12), and only the files they load: no listings, no tests.
	files := http.FileServerFS(s.files)
	mux.Handle("GET /lib/{file}", libFile(files))
	mux.Handle("GET /style.css", files)
	mux.HandleFunc("GET "+links.ApprovalsPath+"{id}", s.page("approve/index.html"))
	mux.HandleFunc("GET "+links.RevertsPath+"{id}", s.page("revert/index.html"))
	mux.HandleFunc("GET "+links.RegisterPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFileFS(w, r, s.files, "register/index.html")
	})
	mux.HandleFunc("GET /api/v1/approvals/{approvalId}", s.getApproval)
	mux.HandleFunc("POST /api/v1/approvals/{approvalId}/approve", s.postApproval)
	mux.HandleFunc("GET /api/v1/reverts/{revertId}", s.getRevert)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/apply", s.postRevert)
	return mux
}

// libFile serves the pages' scripts, lib/*.js, and nothing else there.
func libFile(files http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path.Ext(r.PathValue("file")) != ".js" {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// page serves the page a short link opens; the page reads the id from its
// path. Not an id: 404, like any other unknown path.
func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := uuid.Parse(r.PathValue("id")); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFileFS(w, r, s.files, name)
	}
}

func (s *Server) getApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "approvalId")
	if !ok {
		return
	}
	req, err := find(r.Context(), s, func(ctx context.Context, a Agent) (approval.Request, error) { return a.ApprovalRequest(ctx, id) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, req)
}

func (s *Server) postApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "approvalId")
	if !ok {
		return
	}
	body, ok := s.body(w, r)
	if !ok {
		return
	}
	// The body is the JSON the approval code carries; parsing it as that
	// code reuses the code's strict decoding (unknown fields, base64url).
	resp, err := approval.ParseResponse(approval.ResponsePrefix + passkey.Bytes(body).String())
	if err != nil || resp.ApprovalID != id {
		s.fail(w, &mcp.ToolError{Code: agent.CodeInvalidArgument, Message: "the body is not this approval's signed response"})
		return
	}
	if _, err := find(r.Context(), s, func(ctx context.Context, a Agent) (struct{}, error) { return struct{}{}, a.RelayApproval(ctx, resp) }); err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, approvedDTO{ApprovalID: id.String(), Status: "APPROVED"})
}

// approvedDTO is the relay's answer for an approval.
type approvedDTO struct {
	ApprovalID string `json:"approvalId"`
	Status     string `json:"status"`
}

func (s *Server) getRevert(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "revertId")
	if !ok {
		return
	}
	req, err := find(r.Context(), s, func(ctx context.Context, a Agent) (revert.Request, error) { return a.RevertRequest(ctx, id) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, req)
}

func (s *Server) postRevert(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r, "revertId")
	if !ok {
		return
	}
	body, ok := s.body(w, r)
	if !ok {
		return
	}
	resp, err := revert.ParseResponse(revert.ResponsePrefix + passkey.Bytes(body).String())
	if err != nil || resp.RevertID != id {
		s.fail(w, &mcp.ToolError{Code: agent.CodeInvalidArgument, Message: "the body is not this revert's signed response"})
		return
	}
	out, err := find(r.Context(), s, func(ctx context.Context, a Agent) (guard.AppliedRevert, error) { return a.RelayRevert(ctx, resp) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, out)
}

// find asks each agent in turn and answers with the first that knows the
// id; none does: NOT_FOUND.
func find[T any](ctx context.Context, s *Server, ask func(context.Context, Agent) (T, error)) (T, error) {
	s.mu.RLock()
	agents := s.agents
	s.mu.RUnlock()
	for _, a := range agents {
		out, err := ask(ctx, a)
		if errors.Is(err, agent.ErrNotThisAgent) {
			continue
		}
		return out, err
	}
	var zero T
	return zero, &mcp.ToolError{Code: agent.CodeNotFound, Message: "no held write or revert with this id: check the link, or ask the agent for it again"}
}

func (s *Server) pathID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		s.fail(w, &mcp.ToolError{Code: agent.CodeInvalidArgument, Message: name + " must be a uuid"})
		return uuid.Nil, false
	}
	return id, true
}

// body reads a relayed signature: only from the page's own origin, only
// JSON, at most maxBody bytes. With no CORS headers on this listener,
// another site's page can make none of these posts.
func (s *Server) body(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Header.Get("Origin") != s.origin {
		writeError(w, http.StatusForbidden, agent.CodePermissionDenied, "the request does not come from the approval page")
		return nil, false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, agent.CodeInvalidArgument, "the body must be application/json")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, agent.CodeInvalidArgument, "the body is too large")
		return nil, false
	case err != nil:
		writeError(w, http.StatusBadRequest, agent.CodeInvalidArgument, "cannot read the body")
		return nil, false
	}
	return body, true
}

// statuses maps contract error codes to HTTP statuses (CONTRACT.md, Local
// pages, Errors).
var statuses = map[string]int{
	agent.CodeNotFound:              http.StatusNotFound,
	agent.CodeApprovalExpired:       http.StatusGone,
	string(guard.CodeRevertExpired): http.StatusGone,
	agent.CodeApprovalInvalid:       http.StatusConflict,
	string(guard.CodeRevertInvalid): http.StatusConflict,
	agent.CodeInvalidArgument:       http.StatusBadRequest,
	agent.CodeUnavailable:           http.StatusServiceUnavailable,
}

// fail answers err as the contract's error body. Unexpected errors are
// logged and answered INTERNAL without their text.
func (s *Server) fail(w http.ResponseWriter, err error) {
	te := agent.ToolError(err)
	status, ok := statuses[te.Code]
	if !ok {
		status = http.StatusInternalServerError
	}
	if status == http.StatusInternalServerError {
		s.log.Error("pages", "err", err)
	}
	writeError(w, status, te.Code, te.Message)
}

// errorDTO is the pages' error body.
type errorDTO struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorDTO{Code: code, Message: message})
}

func (s *Server) reply(w http.ResponseWriter, v any) {
	writeJSON(w, http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal engine error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n')) // the page may have gone; nothing to do
}
