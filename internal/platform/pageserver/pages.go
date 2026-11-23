// Package pageserver serves the approval and revert pages from the engine on a
// loopback listener, with a same-origin relay for them (CONTRACT.md, Local
// pages): a short link /approvals/<id> or /reverts/<id> opens the page, the
// page reads the request for that id from the engine, and after the
// person's passkey signs it posts the signature back for the engine to
// relay with the agent's credential. The relay decides nothing: Postgres
// verifies the signature.
package pageserver

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
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/web"
)

// maxBody bounds a relayed signature (the response JSON is about 1 KiB).
const maxBody = 16 << 10

// Agent is one agent the engine serves, as the pages use it.
// agent.ErrNotThisAgent means the id is not this agent's.
type Agent interface {
	ApprovalRequest(ctx context.Context, id uuid.UUID) (approval.Request, error)
	// RelayApproval and RelayRevert relay the person's signature and return
	// the engine's receipt of it (CONTRACT.md, Vault channel, Receipts).
	RelayApproval(ctx context.Context, r approval.Response) (agent.Receipt, error)
	// RevertRequest is the request for the page holding secret, the
	// revert's live link secret.
	RevertRequest(ctx context.Context, id uuid.UUID, secret string) (revert.Request, error)
	RelayRevert(ctx context.Context, r revert.Response) (action.AppliedRevert, agent.Receipt, error)
	// RescopeRevert changes the revert's scope for the page holding secret
	// (CONTRACT.md, Rescope, widen and reject).
	RescopeRevert(ctx context.Context, id uuid.UUID, secret string, in agent.ScopeRequest) (agent.ScopeResponse, error)
	// RejectRevert rejects the revert for the page holding secret and
	// revokes its link (CONTRACT.md, Rescope, widen and reject).
	RejectRevert(ctx context.Context, id uuid.UUID, secret string, in agent.RejectRequest) (agent.RejectResponse, error)
	// RevealApproval and RevealRevert return the values of the item's
	// redacted lines for the person's reveal proof (CONTRACT.md, Rows hidden
	// from the agent), for the page holding secret.
	RevealApproval(ctx context.Context, id uuid.UUID, secret string, in agent.RevealRequest) (approval.RevealAnswer, error)
	RevealRevert(ctx context.Context, id uuid.UUID, secret string, in agent.RevealRequest) (approval.RevealAnswer, error)
	// CheckLink reports whether secret is the live link secret of one of
	// this agent's items (CONTRACT.md, Link secrets).
	CheckLink(id uuid.UUID, secret string) bool
	// CheckResetLink reports whether secret is a link of revert id that the
	// agent's reset revoked (NOT_FOUND reason LINK_RESET).
	CheckResetLink(id uuid.UUID, secret string) bool
	// PageFailure is err as the pages answer it: the error body with the
	// person's message and steps (CONTRACT.md, Next steps).
	PageFailure(err error) *toolresult.ToolError
}

// PluginApprovals is what the plugin approval routes ask of an agent
// (CONTRACT.md, Local pages): an Agent that also serves plugin approvals
// implements it, and the routes skip one that does not, as an agent that
// does not know the id. Each method acts on a plugin approval this agent's
// role opened, with its credential; ErrNotThisAgent (agent package) means
// another agent's, or none.
type PluginApprovals interface {
	// PluginApprovalRequest is the request of a pending plugin approval:
	// its binding and settings texts read from agent_plugin_approvals, and
	// the database's passkeys.
	PluginApprovalRequest(ctx context.Context, id uuid.UUID) (approval.PluginRequest, error)
	// RelayPluginApproval relays the person's signature to
	// submit_plugin_approval, which verifies it, and returns when Postgres
	// recorded the approval.
	RelayPluginApproval(ctx context.Context, r approval.PluginApprovalResponse) (time.Time, error)
}

// Server is the pages' handler. Agents are added once each is set up,
// before the listener serves.
type Server struct {
	origin string
	log    *slog.Logger
	files  fs.FS
	mu     sync.RWMutex
	agents []Agent
	// The handlers app mounts on the API routes, one set per page
	// (MountApprovals, MountReverts, MountPlugins). Handler and Dispatch
	// need all three.
	approvals ApprovalHandlers
	reverts   RevertHandlers
	plugins   PluginHandlers
	// setup serves the setup page and its routes (MountSetup); Handler
	// needs it, Dispatch never reaches it.
	setup SetupHandlers
}

// Setup paths (CONTRACT.md, The local setup page).
const (
	SetupPagePath  = "/setup/"
	SetupCheckPath = "/api/v1/setup/check"
	SetupRunPath   = "/api/v1/setup/run"
	// SetupDoctorPath is the Update check: no admin string.
	SetupDoctorPath  = "/api/v1/setup/doctor"
	SetupEnginePath  = "/api/v1/setup/engine"
	SetupNotMinePath = "/api/v1/setup/not-mine"
)

// SetupHandlers serve the setup page (GET SetupPagePath) and its routes.
// Whatever is mounted, Handler refuses a databaseUrl body on every other
// loopback route (refuseDatabaseURL).
type SetupHandlers struct {
	Page, Check, Run, Doctor, Engine, NotMine http.HandlerFunc
}

// MountSetup serves h on the setup routes; a later call replaces an
// earlier one. Call it before Handler.
func (s *Server) MountSetup(h SetupHandlers) {
	if h.Page == nil || h.Check == nil || h.Run == nil || h.Doctor == nil || h.Engine == nil || h.NotMine == nil {
		panic("pages: every setup handler required")
	}
	s.setup = h
}

// ApprovalHandlers serve the approval page's API routes: GET the request,
// POST …/approve and POST …/reveal.
type ApprovalHandlers struct {
	Get, Approve, Reveal http.HandlerFunc
}

// RevertHandlers serve the revert page's API routes: GET the request, POST
// …/apply, …/scope, …/reject and …/reveal.
type RevertHandlers struct {
	Get, Apply, Scope, Reject, Reveal http.HandlerFunc
}

// PluginHandlers serve the plugin approval page's API routes: GET the
// request and POST …/approve.
type PluginHandlers struct {
	Get, Approve http.HandlerFunc
}

// MountApprovals serves h on the approval routes. Call it before Handler
// or Dispatch.
func (s *Server) MountApprovals(h ApprovalHandlers) {
	if h.Get == nil || h.Approve == nil || h.Reveal == nil {
		panic("pages: every approval handler required")
	}
	s.approvals = h
}

// MountReverts serves h on the revert routes. Call it before Handler or
// Dispatch.
func (s *Server) MountReverts(h RevertHandlers) {
	if h.Get == nil || h.Apply == nil || h.Scope == nil || h.Reject == nil || h.Reveal == nil {
		panic("pages: every revert handler required")
	}
	s.reverts = h
}

// MountPlugins serves h on the plugin approval routes. Call it before
// Handler or Dispatch.
func (s *Server) MountPlugins(h PluginHandlers) {
	if h.Get == nil || h.Approve == nil {
		panic("pages: every plugin approval handler required")
	}
	s.plugins = h
}

// mounted panics unless app mounted every page's handlers.
func (s *Server) mounted() {
	if s.approvals.Get == nil || s.reverts.Get == nil || s.plugins.Get == nil {
		panic("pages: mount the approval, revert and plugin handlers first")
	}
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
	s.mounted()
	if s.setup.Page == nil {
		panic("pages: mount the setup handlers first")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	// The pages at their RESTful paths (links; owner decisions, Decided
	// Nov 12), and only the files they load: no listings, no tests.
	files := http.FileServerFS(s.files)
	mux.Handle("GET /lib/{file}", LibFile(files))
	mux.Handle("GET /style.css", files)
	mux.Handle("GET /fonts/{file}", FontFile(files))
	for _, r := range web.PageRoutes {
		if r.ID {
			mux.HandleFunc("GET "+r.Path+"{id}", s.page(r.File))
		} else {
			mux.HandleFunc("GET "+r.Path, s.static(r.File))
		}
	}
	mux.HandleFunc("GET /api/v1/approvals/{approvalId}", s.approvals.Get)
	mux.HandleFunc("POST /api/v1/approvals/{approvalId}/approve", s.approvals.Approve)
	mux.HandleFunc("GET /api/v1/reverts/{revertId}", s.reverts.Get)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/apply", s.reverts.Apply)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/scope", s.reverts.Scope)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/reject", s.reverts.Reject)
	mux.HandleFunc("POST /api/v1/approvals/{approvalId}/reveal", s.approvals.Reveal)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/reveal", s.reverts.Reveal)
	mux.HandleFunc("GET "+SetupPagePath+"{$}", s.setup.Page)
	mux.HandleFunc("POST "+SetupCheckPath, s.setup.Check)
	mux.HandleFunc("POST "+SetupRunPath, s.setup.Run)
	mux.HandleFunc("POST "+SetupDoctorPath, s.setup.Doctor)
	mux.HandleFunc("POST "+SetupEnginePath, s.setup.Engine)
	mux.HandleFunc("POST "+SetupNotMinePath, s.setup.NotMine)
	mux.HandleFunc("GET /api/v1/plugins/{approvalId}", s.plugins.Get)
	mux.HandleFunc("POST /api/v1/plugins/{approvalId}/approve", s.plugins.Approve)
	return refuseDatabaseURL(s.origin, mux)
}

// LibFile serves the pages' scripts, lib/*.js, and nothing else there.
func LibFile(files http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path.Ext(r.PathValue("file")) != ".js" {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// FontFile serves the pages' fonts, fonts/*.woff2, and their license.
func FontFile(files http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch file := r.PathValue("file"); {
		case path.Ext(file) == ".woff2":
			w.Header().Set("Content-Type", "font/woff2")
		case file == "OFL.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		default:
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

// Reveal shows the person the values of the redacted lines of the item
// named by the path parameter name, as ask returns them (CONTRACT.md, Local
// pages, POST …/reveal): the approval and revert pages share it. The body
// is decoded strictly, { "proof", "revealSecret" }; Postgres checks the
// proof. The answer is sent with Cache-Control: no-store (WriteJSON) and
// kept nowhere.
func (s *Server) Reveal(w http.ResponseWriter, r *http.Request, name string,
	ask func(context.Context, Agent, uuid.UUID, string, agent.RevealRequest) (approval.RevealAnswer, error),
) {
	id, ok := s.LinkedID(w, r, name)
	if !ok {
		return
	}
	body, ok := s.Body(w, r)
	if !ok {
		return
	}
	in, ok := revealBody(body)
	if !ok {
		s.Fail(w, &toolresult.ToolError{
			Code:    agent.CodeInvalidArgument,
			Message: "the body must be {\"proof\", \"revealSecret\"} (reveal-request.schema.json)",
		})
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	out, err := Find(r.Context(), s, func(ctx context.Context, a Agent) (approval.RevealAnswer, error) {
		return ask(ctx, a, id, secret, in)
	})
	if err != nil {
		s.Fail(w, err)
		return
	}
	s.Reply(w, out)
}

// revealBody decodes a reveal body strictly: no unknown key, every proof
// field and the secret present.
func revealBody(body []byte) (agent.RevealRequest, bool) {
	var in agent.RevealRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() {
		return agent.RevealRequest{}, false
	}
	p := in.Proof
	complete := len(p.CredentialID) > 0 && len(p.AuthenticatorData) > 0 && len(p.ClientDataJSON) > 0 && len(p.Signature) > 0
	return in, complete && in.RevealSecret != ""
}

// LinkedID is the id in the path parameter name when the request carries
// that item's live link secret (CONTRACT.md, Link secrets). A missing,
// wrong or revoked secret is answered exactly as an unknown id, before any
// lookup; false means the answer is written.
func (s *Server) LinkedID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, ok := s.pathID(w, r, name)
	if !ok {
		return uuid.Nil, false
	}
	secret := r.Header.Get(links.SecretHeader)
	if !s.linkLive(id, secret) {
		s.Fail(w, s.deadLink(id, secret))
		return uuid.Nil, false
	}
	return id, true
}

// deadLink is the answer for a secret that is not id's live link: LINK_RESET
// when the agent's reset revoked it, so the page can say why, else the
// same answer as an unknown id. Every agent is asked, as by linkLive.
func (s *Server) deadLink(id uuid.UUID, secret string) error {
	s.mu.RLock()
	agents := s.agents
	s.mu.RUnlock()
	reset := false
	for _, a := range agents {
		reset = a.CheckResetLink(id, secret) || reset
	}
	if !reset {
		return unknownLink()
	}
	te, err := agent.LinkReset()
	if err != nil {
		return err
	}
	return te
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

// Find asks each of s's agents in turn and answers with the first that
// knows the id; none does: NOT_FOUND, reason LINK, the same as a link
// without its secret: the two are told apart by nothing.
func Find[T any](ctx context.Context, s *Server, ask func(context.Context, Agent) (T, error)) (T, error) {
	s.mu.RLock()
	agents := s.agents
	s.mu.RUnlock()
	for _, a := range agents {
		out, err := ask(ctx, a)
		if errors.Is(err, agent.ErrNotThisAgent) {
			continue
		}
		if err != nil {
			return out, pageFailure(a, err)
		}
		return out, nil
	}
	var zero T
	return zero, unknownLink()
}

// nonceError is a page failure that hands the page the nonce of the widen
// it asks the person for (a widened revert the engine no longer holds).
type nonceError struct {
	*toolresult.ToolError
	nonce passkey.Bytes
}

func (e *nonceError) Unwrap() error { return e.ToolError }

// pageFailure is a's answer for err, keeping a rescope nonce it carries.
func pageFailure(a Agent, err error) error {
	te := a.PageFailure(err)
	var pe *agent.PageError
	if errors.As(err, &pe) && pe.RescopeNonce != nil {
		return &nonceError{ToolError: te, nonce: pe.RescopeNonce}
	}
	return te
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
		s.Fail(w, &toolresult.ToolError{Code: agent.CodeInvalidArgument, Message: name + " must be a uuid"})
		return uuid.Nil, false
	}
	return id, true
}

// Body reads a posted body: only from the page's own origin, only JSON, at most
// maxBody bytes. With no CORS headers on this listener, another site's
// page can make none of these posts. False means the answer is written.
func (s *Server) Body(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Header.Get("Origin") != s.origin {
		WriteError(w, http.StatusForbidden, agent.CodePermissionDenied, "the request does not come from the approval page")
		return nil, false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		WriteError(w, http.StatusUnsupportedMediaType, agent.CodeInvalidArgument, "the body must be application/json")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		WriteError(w, http.StatusRequestEntityTooLarge, agent.CodeInvalidArgument, "the body is too large")
		return nil, false
	case err != nil:
		WriteError(w, http.StatusBadRequest, agent.CodeInvalidArgument, "cannot read the body")
		return nil, false
	}
	return body, true
}

// statuses maps contract error codes to HTTP statuses (CONTRACT.md, Local
// pages, Errors).
var statuses = map[string]int{
	agent.CodeNotFound:                   http.StatusNotFound,
	agent.CodeApprovalExpired:            http.StatusGone,
	string(guardmodel.CodeRevertExpired): http.StatusGone,
	agent.CodeApprovalInvalid:            http.StatusConflict,
	string(guardmodel.CodeRevertInvalid): http.StatusConflict,
	agent.CodeInvalidArgument:            http.StatusBadRequest,
	agent.CodeUnavailable:                http.StatusServiceUnavailable,
	agent.CodeQueryTimeout:               http.StatusGatewayTimeout,
}

// Fail answers err as the contract's error body. Unexpected errors are
// logged and answered INTERNAL without their text.
func (s *Server) Fail(w http.ResponseWriter, err error) {
	// Every failure here is the pages' own or the agent's PageFailure, so it
	// is already the contract's error body; anything else is the engine's.
	var te *toolresult.ToolError
	if !errors.As(err, &te) {
		te = &toolresult.ToolError{Code: agent.CodeInternal, Message: "internal engine error"}
	}
	status, ok := statuses[te.Code]
	if !ok {
		status = http.StatusInternalServerError
	}
	if status == http.StatusInternalServerError {
		s.log.Error("pages", "err", err)
	}
	dto := ErrorDTO{
		Code: te.Code, Message: te.Message, Reason: te.Reason, PersonMessage: te.PersonMessage, NextSteps: personSteps(te.NextSteps),
	}
	var ne *nonceError
	if errors.As(err, &ne) {
		dto.RescopeNonce = ne.nonce
	}
	WriteJSON(w, status, dto)
}

// ErrorDTO is the pages' error body: the contract's tool error as the page
// shows it, with the person's message and only the steps for the person.
type ErrorDTO struct {
	Code          string                `json:"code"`
	Message       string                `json:"message"`
	Reason        string                `json:"reason,omitempty"`
	PersonMessage string                `json:"personMessage,omitempty"`
	NextSteps     []toolresult.NextStep `json:"nextSteps,omitempty"`
	// RescopeNonce is set only on the 409 for a widened revert the engine
	// no longer holds: the nonce of the person's new widen proof.
	RescopeNonce passkey.Bytes `json:"rescopeNonce,omitempty"`
}

// WriteError answers the error body with only code and message.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorDTO{Code: code, Message: message})
}

// personSteps are the steps the person takes: the page shows them, and the
// agent's steps go to the agent through its own tools.
func personSteps(steps []toolresult.NextStep) []toolresult.NextStep {
	var out []toolresult.NextStep
	for _, st := range steps {
		if st.Actor == toolresult.ActorPerson {
			out = append(out, st)
		}
	}
	return out
}

// Reply answers v as JSON, 200.
func (s *Server) Reply(w http.ResponseWriter, v any) {
	WriteJSON(w, http.StatusOK, v)
}

// WriteJSON answers v as JSON with status, never cached.
func WriteJSON(w http.ResponseWriter, status int, v any) {
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

// refuseDatabaseURL refuses, on every route but the setup page's two, a
// body that holds a databaseUrl field, in any case: only those take the
// admin connection string. A request from a foreign Origin goes on to its
// route, which refuses it before reading anything. A body within the
// pages' limit is parsed; a larger one, read up to scanLimit, is refused
// when it names the field anywhere. Either is handed on unchanged, and the
// route refuses what is too large.
func refuseDatabaseURL(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := r.Header.Get("Origin")
		if r.Method != http.MethodPost || r.URL.Path == SetupCheckPath || r.URL.Path == SetupRunPath || r.Body == nil ||
			(o != "" && o != origin) {
			next.ServeHTTP(w, r)
			return
		}
		head, err := io.ReadAll(io.LimitReader(r.Body, scanLimit))
		if err == nil && namesDatabaseURL(head) {
			WriteError(w, http.StatusBadRequest, agent.CodeInvalidArgument, "This route never takes the admin connection string.")
			return
		}
		r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(head), r.Body), Closer: r.Body}
		next.ServeHTTP(w, r)
	})
}

// scanLimit bounds how much of an oversized body the scan reads.
const scanLimit = 1 << 20

// databaseURLKey is the field only the setup routes take, compared without
// case.
const databaseURLKey = "databaseurl"

// namesDatabaseURL: a body within the limit has the field at any depth; a
// larger one names it anywhere in what was read.
func namesDatabaseURL(head []byte) bool {
	if len(head) > maxBody {
		return bytes.Contains(bytes.ToLower(head), []byte(databaseURLKey))
	}
	return HoldsDatabaseURL(head)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// HoldsDatabaseURL reports whether a JSON body has a databaseUrl field at
// any depth: only the setup routes take the admin connection string.
func HoldsDatabaseURL(body []byte) bool {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	return hasKey(v, databaseURLKey)
}

func hasKey(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if strings.EqualFold(k, key) || hasKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if hasKey(child, key) {
				return true
			}
		}
	}
	return false
}
