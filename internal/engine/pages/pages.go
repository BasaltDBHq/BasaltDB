// Package pages serves the approval and revert pages from the engine on a
// loopback listener, with a same-origin relay for them (CONTRACT.md, Local
// pages): a short link /approvals/<id> or /reverts/<id> opens the page, the
// page reads the request for that id from the engine, and after the
// person's passkey signs it posts the signature back for the engine to
// relay with the agent's credential. The relay decides nothing: Postgres
// verifies the signature.
package pages

import (
	"bytes"
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

// PageRoute is a page the engine serves at a RESTful path. ID routes take
// one uuid after Path (/approvals/<id>); the others are exactly Path. The
// portal's static host must rewrite the same paths to the same files:
// web/_redirects, which a test checks against PageRoutes.
type PageRoute struct {
	Path string
	ID   bool
	File string
}

// PageRoutes are the pages, in the order they are registered.
var PageRoutes = []PageRoute{
	{Path: links.ApprovalsPath, ID: true, File: "approve/index.html"},
	{Path: links.RevertsPath, ID: true, File: "revert/index.html"},
	{Path: links.RegisterPath, File: "register/index.html"},
	// The passkey management page (M4.1): static, input in the fragment,
	// no relay.
	{Path: links.CheckPath, File: "passkeys/index.html"},
	{Path: links.ForgetPath, File: "passkeys/index.html"},
}

// maxBody bounds a relayed signature (the response JSON is about 1 KiB).
const maxBody = 16 << 10

// Agent is one agent the engine serves, as the pages use it.
// agent.ErrNotThisAgent means the id is not this agent's.
type Agent interface {
	ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error)
	RelayApproval(ctx context.Context, r approval.Response) error
	RevertRequest(ctx context.Context, id uuid.UUID) (revert.Request, error)
	RelayRevert(ctx context.Context, r revert.Response) (guard.AppliedRevert, error)
	IssueApprovalLink(ctx context.Context, id uuid.UUID, proof string) (string, error)
	IssueRevertLink(ctx context.Context, id uuid.UUID, proof string) (string, error)
	// CheckLink reports whether secret is the live link secret of one of
	// this agent's items (CONTRACT.md, Link secrets).
	CheckLink(id uuid.UUID, secret string) bool
	// PageFailure is err as the pages answer it: the error body with the
	// person's message and steps (CONTRACT.md, Next steps).
	PageFailure(err error) *mcp.ToolError
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
// relayed POST must come from. The page files are the ones embedded in the
// binary: after editing web/, rebuild and restart the engine.
func New(origin string, log *slog.Logger) *Server {
	if origin == "" || log == nil {
		panic("pages: origin and logger required")
	}
	return &Server{origin: origin, log: log, files: web.Files}
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
	for _, r := range PageRoutes {
		if r.ID {
			mux.HandleFunc("GET "+r.Path+"{id}", s.page(r.File))
		} else {
			mux.HandleFunc("GET "+r.Path, s.static(r.File))
		}
	}
	mux.HandleFunc("GET /api/v1/approvals/{approvalId}", s.getApproval)
	mux.HandleFunc("POST /api/v1/approvals/{approvalId}/approve", s.postApproval)
	mux.HandleFunc("GET /api/v1/reverts/{revertId}", s.getRevert)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/apply", s.postRevert)
	mux.HandleFunc("POST /api/v1/approvals/{approvalId}/links", s.postApprovalLink)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/links", s.postRevertLink)
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

// static serves a page that takes everything from its URL fragment.
func (s *Server) static(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFileFS(w, r, s.files, name)
	}
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
	id, ok := s.linkedID(w, r, "approvalId")
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
	id, ok := s.linkedID(w, r, "approvalId")
	if !ok {
		return
	}
	body, ok := s.body(w, r, pageOnly)
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
	id, ok := s.linkedID(w, r, "revertId")
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
	id, ok := s.linkedID(w, r, "revertId")
	if !ok {
		return
	}
	body, ok := s.body(w, r, pageOnly)
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

// issueDTO asks for a short link (POST .../links): proof of the item's
// binding text (links.IssueProof).
type issueDTO struct {
	Proof string `json:"proof"`
}

// linkDTO is a newly issued short link.
type linkDTO struct {
	URL string `json:"url"`
}

func (s *Server) postApprovalLink(w http.ResponseWriter, r *http.Request) {
	s.issueLink(w, r, "approvalId", func(ctx context.Context, a Agent, id uuid.UUID, proof string) (string, error) {
		return a.IssueApprovalLink(ctx, id, proof)
	})
}

func (s *Server) postRevertLink(w http.ResponseWriter, r *http.Request) {
	s.issueLink(w, r, "revertId", func(ctx context.Context, a Agent, id uuid.UUID, proof string) (string, error) {
		return a.IssueRevertLink(ctx, id, proof)
	})
}

// issueLink issues a short link for the CLI, to a caller that shows proof
// of the item's binding text; a wrong proof is answered as an unknown id.
func (s *Server) issueLink(w http.ResponseWriter, r *http.Request, name string,
	issue func(context.Context, Agent, uuid.UUID, string) (string, error)) {
	id, ok := s.pathID(w, r, name)
	if !ok {
		return
	}
	body, ok := s.body(w, r, cliOrPage)
	if !ok {
		return
	}
	var in issueDTO
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.Proof == "" {
		s.fail(w, &mcp.ToolError{Code: agent.CodeInvalidArgument, Message: "the body must be {\"proof\": \"...\"}"})
		return
	}
	link, err := find(r.Context(), s, func(ctx context.Context, a Agent) (string, error) { return issue(ctx, a, id, in.Proof) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, linkDTO{URL: link})
}

// linkedID is the path's id when the request carries that item's live link
// secret (CONTRACT.md, Link secrets). A missing, wrong or revoked secret
// is answered exactly as an unknown id, before any lookup.
func (s *Server) linkedID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, ok := s.pathID(w, r, name)
	if !ok {
		return uuid.Nil, false
	}
	if !s.linkLive(id, r.Header.Get(links.SecretHeader)) {
		s.fail(w, unknownLink())
		return uuid.Nil, false
	}
	return id, true
}

// linkLive reports whether some agent issued secret as id's live link.
// Every agent is asked, so the time taken does not tell which one knows
// the id.
func (s *Server) linkLive(id uuid.UUID, secret string) bool {
	s.mu.RLock()
	agents := s.agents
	s.mu.RUnlock()
	live := false
	for _, a := range agents {
		live = a.CheckLink(id, secret) || live
	}
	return live
}

// find asks each agent in turn and answers with the first that knows the
// id; none does: NOT_FOUND, reason LINK, the same as a link without its
// secret: the two are told apart by nothing.
func find[T any](ctx context.Context, s *Server, ask func(context.Context, Agent) (T, error)) (T, error) {
	s.mu.RLock()
	agents := s.agents
	s.mu.RUnlock()
	for _, a := range agents {
		out, err := ask(ctx, a)
		if errors.Is(err, agent.ErrNotThisAgent) {
			continue
		}
		if err != nil {
			return out, a.PageFailure(err)
		}
		return out, nil
	}
	var zero T
	return zero, unknownLink()
}

// unknownLink is the NOT_FOUND answer for a link no agent knows. Should its
// steps fail to build, the answer is the error itself (INTERNAL).
func unknownLink() error {
	te, err := agent.LinkNotFound()
	if err != nil {
		return err
	}
	return te
}

func (s *Server) pathID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		s.fail(w, &mcp.ToolError{Code: agent.CodeInvalidArgument, Message: name + " must be a uuid"})
		return uuid.Nil, false
	}
	return id, true
}

// Who may post: the relay only from the page's own origin; a link request
// also from the CLI, which sends no Origin.
const (
	pageOnly  = false
	cliOrPage = true
)

// body reads a posted body: from an allowed origin, only JSON, at most
// maxBody bytes. With no CORS headers on this listener, another site's
// page can make none of these posts.
func (s *Server) body(w http.ResponseWriter, r *http.Request, fromCLI bool) ([]byte, bool) {
	origin := r.Header.Get("Origin")
	if origin != s.origin && (!fromCLI || origin != "") {
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
	writeJSON(w, status, errorDTO{
		Code: te.Code, Message: te.Message, Reason: te.Reason, PersonMessage: te.PersonMessage, NextSteps: personSteps(te.NextSteps),
	})
}

// errorDTO is the pages' error body: the contract's tool error as the page
// shows it, with the person's message and only the steps for the person.
type errorDTO struct {
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	Reason        string         `json:"reason,omitempty"`
	PersonMessage string         `json:"personMessage,omitempty"`
	NextSteps     []mcp.NextStep `json:"nextSteps,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorDTO{Code: code, Message: message})
}

// personSteps are the steps the person takes: the page shows them, and the
// agent's steps go to the agent through its own tools.
func personSteps(steps []mcp.NextStep) []mcp.NextStep {
	var out []mcp.NextStep
	for _, st := range steps {
		if st.Actor == mcp.ActorPerson {
			out = append(out, st)
		}
	}
	return out
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
