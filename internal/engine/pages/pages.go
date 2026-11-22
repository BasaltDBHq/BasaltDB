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
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/action"
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
	// The plugin approval page: the same fragments as the approval page
	// (#2., #s=, #h=).
	{Path: links.PluginsPath, ID: true, File: "plugin/index.html"},
	{Path: links.RegisterPath, File: "register/index.html"},
	// The passkey management page (M4.1): static, input in the fragment,
	// no relay.
	{Path: links.CheckPath, File: "passkeys/index.html"},
	{Path: links.ForgetPath, File: "passkeys/index.html"},
}

// PortalRoutes are pages only the portal serves: the connect page
// (CONTRACT.md, The connect page), where the connect service runs a setup
// code. The engine embeds its file, so basalt portal verify checks it, but
// never serves it: the connect service allows only the portal.
var PortalRoutes = []PageRoute{
	{Path: links.ConnectPath, File: "connect/index.html"},
}

// PortalPages are every page the portal serves: PageRoutes, then
// PortalRoutes.
func PortalPages() []PageRoute {
	return append(append([]PageRoute{}, PageRoutes...), PortalRoutes...)
}

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
	IssueApprovalLink(ctx context.Context, id uuid.UUID, proof string) (string, error)
	IssueRevertLink(ctx context.Context, id uuid.UUID, proof string) (string, error)
	// CheckLink reports whether secret is the live link secret of one of
	// this agent's items (CONTRACT.md, Link secrets).
	CheckLink(id uuid.UUID, secret string) bool
	// CheckResetLink reports whether secret is a link of revert id that the
	// agent's reset revoked (NOT_FOUND reason LINK_RESET).
	CheckResetLink(id uuid.UUID, secret string) bool
	// PageFailure is err as the pages answer it: the error body with the
	// person's message and steps (CONTRACT.md, Next steps).
	PageFailure(err error) *mcp.ToolError
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
	// setup runs the setup page's UPDATE and REMOVE (SetSetup); nil
	// refuses every setup request JOB_UNAVAILABLE without reading it.
	setup SetupJobs
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

// SetSetup serves the setup page's jobs for this engine's agents
// (CONTRACT.md, The local setup page): the only routes that read the admin
// connection string. Call it before Handler.
func (s *Server) SetSetup(jobs SetupJobs) { s.setup = jobs }

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
	mux.Handle("GET /fonts/{file}", fontFile(files))
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
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/scope", s.postScope)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/reject", s.postReject)
	mux.HandleFunc("POST /api/v1/approvals/{approvalId}/reveal", s.postApprovalReveal)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/reveal", s.postRevertReveal)
	mux.HandleFunc("POST /api/v1/approvals/{approvalId}/links", s.postApprovalLink)
	mux.HandleFunc("POST /api/v1/reverts/{revertId}/links", s.postRevertLink)
	mux.HandleFunc("GET "+SetupPagePath+"{$}", serveSetupPage)
	if s.setup != nil {
		st := setupRoutes{origin: s.origin, jobs: s.setup, log: s.log.With("component", "setup")}
		mux.HandleFunc("POST "+SetupCheckPath, st.check)
		mux.HandleFunc("POST "+SetupRunPath, st.run)
	} else {
		mux.HandleFunc("POST "+SetupCheckPath, s.configuredSetup)
		mux.HandleFunc("POST "+SetupRunPath, s.configuredSetup)
	}
	mux.HandleFunc("GET /api/v1/plugins/{approvalId}", s.getPlugin)
	mux.HandleFunc("POST /api/v1/plugins/{approvalId}/approve", s.postPlugin)
	return refuseDatabaseURL(s.origin, mux)
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

// fontFile serves the pages' fonts, fonts/*.woff2, and their license.
func fontFile(files http.Handler) http.Handler {
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

func (s *Server) getApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := s.linkedID(w, r, approvalParam)
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
	id, ok := s.linkedID(w, r, approvalParam)
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
	receipt, err := find(r.Context(), s, func(ctx context.Context, a Agent) (agent.Receipt, error) { return a.RelayApproval(ctx, resp) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, approvedDTO{ApprovalID: id.String(), Status: "APPROVED", Receipt: receipt.Token, NoReceipt: receipt.Missing})
}

// approvedDTO is the relay's answer for an approval, with the engine's
// receipt or why there is none.
type approvedDTO struct {
	ApprovalID string `json:"approvalId"`
	Status     string `json:"status"`
	Receipt    string `json:"receipt,omitempty"`
	NoReceipt  string `json:"noReceipt,omitempty"`
}

// appliedDTO is the relay's answer for a revert: the result basalt revert
// --apply --json prints, with the engine's receipt or why there is none.
type appliedDTO struct {
	action.AppliedRevert
	Receipt   string `json:"receipt,omitempty"`
	NoReceipt string `json:"noReceipt,omitempty"`
}

// relayedRevert is what RelayRevert returns, for find.
type relayedRevert struct {
	applied action.AppliedRevert
	receipt agent.Receipt
}

func (s *Server) getRevert(w http.ResponseWriter, r *http.Request) {
	id, ok := s.linkedID(w, r, revertParam)
	if !ok {
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	req, err := find(r.Context(), s, func(ctx context.Context, a Agent) (revert.Request, error) { return a.RevertRequest(ctx, id, secret) })
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, req)
}

func (s *Server) postRevert(w http.ResponseWriter, r *http.Request) {
	id, ok := s.linkedID(w, r, revertParam)
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
	out, err := find(r.Context(), s, func(ctx context.Context, a Agent) (relayedRevert, error) {
		applied, receipt, err := a.RelayRevert(ctx, resp)
		return relayedRevert{applied: applied, receipt: receipt}, err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, appliedDTO{AppliedRevert: out.applied, Receipt: out.receipt.Token, NoReceipt: out.receipt.Missing})
}

// postScope narrows or widens a revert's scope for the page (CONTRACT.md,
// Local pages, POST …/scope). The body is decoded strictly: an unknown key
// (the reserved store included) or a proof without its new secret is
// refused on its shape, before anything is looked up. Postgres checks the
// rest in the contract's order.
func (s *Server) postScope(w http.ResponseWriter, r *http.Request) {
	id, ok := s.linkedID(w, r, revertParam)
	if !ok {
		return
	}
	body, ok := s.body(w, r, pageOnly)
	if !ok {
		return
	}
	var in agent.ScopeRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() || (in.Proof == nil) != (in.NewSecret == "") {
		s.fail(w, &mcp.ToolError{
			Code:    agent.CodeInvalidArgument,
			Message: "the body must be {\"select\", \"proof\"?, \"newSecret\"?} (revert-scope-request.schema.json), proof and newSecret together",
		})
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	out, err := find(r.Context(), s, func(ctx context.Context, a Agent) (agent.ScopeResponse, error) {
		return a.RescopeRevert(ctx, id, secret, in)
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, out)
}

// postReject rejects a revert for the page (CONTRACT.md, Local pages, POST
// …/reject). The body is decoded strictly, { "note"? }; the note's length is
// the service's to check. Postgres decides the rest.
func (s *Server) postReject(w http.ResponseWriter, r *http.Request) {
	id, ok := s.linkedID(w, r, revertParam)
	if !ok {
		return
	}
	body, ok := s.body(w, r, pageOnly)
	if !ok {
		return
	}
	var in agent.RejectRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() {
		s.fail(w, &mcp.ToolError{
			Code:    agent.CodeInvalidArgument,
			Message: "the body must be {\"note\"?} (revert-reject-request.schema.json)",
		})
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	out, err := find(r.Context(), s, func(ctx context.Context, a Agent) (agent.RejectResponse, error) {
		return a.RejectRevert(ctx, id, secret, in)
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, out)
}

// postApprovalReveal and postRevertReveal show the person the values of
// the item's redacted lines (CONTRACT.md, Local pages, POST …/reveal). The
// body is decoded strictly, { "proof", "revealSecret" }; Postgres checks
// the proof. The answer is sent with Cache-Control: no-store (writeJSON)
// and kept nowhere.
func (s *Server) postApprovalReveal(w http.ResponseWriter, r *http.Request) {
	s.reveal(w, r, approvalParam, func(ctx context.Context, a Agent, id uuid.UUID, secret string, in agent.RevealRequest) (approval.RevealAnswer, error) {
		return a.RevealApproval(ctx, id, secret, in)
	})
}

func (s *Server) postRevertReveal(w http.ResponseWriter, r *http.Request) {
	s.reveal(w, r, revertParam, func(ctx context.Context, a Agent, id uuid.UUID, secret string, in agent.RevealRequest) (approval.RevealAnswer, error) {
		return a.RevealRevert(ctx, id, secret, in)
	})
}

func (s *Server) reveal(w http.ResponseWriter, r *http.Request, name string,
	ask func(context.Context, Agent, uuid.UUID, string, agent.RevealRequest) (approval.RevealAnswer, error),
) {
	id, ok := s.linkedID(w, r, name)
	if !ok {
		return
	}
	body, ok := s.body(w, r, pageOnly)
	if !ok {
		return
	}
	in, ok := revealBody(body)
	if !ok {
		s.fail(w, &mcp.ToolError{
			Code:    agent.CodeInvalidArgument,
			Message: "the body must be {\"proof\", \"revealSecret\"} (reveal-request.schema.json)",
		})
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	out, err := find(r.Context(), s, func(ctx context.Context, a Agent) (approval.RevealAnswer, error) {
		return ask(ctx, a, id, secret, in)
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, out)
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
	s.issueLink(w, r, approvalParam, func(ctx context.Context, a Agent, id uuid.UUID, proof string) (string, error) {
		return a.IssueApprovalLink(ctx, id, proof)
	})
}

func (s *Server) postRevertLink(w http.ResponseWriter, r *http.Request) {
	s.issueLink(w, r, revertParam, func(ctx context.Context, a Agent, id uuid.UUID, proof string) (string, error) {
		return a.IssueRevertLink(ctx, id, proof)
	})
}

// The plugin approval routes (CONTRACT.md, Local pages): the same link
// secret, origin, content type and size checks as the approval routes. The
// relay decides nothing: submit_plugin_approval verifies the signature.

// pluginApprovedDTO is the relay's answer for a plugin approval: no
// receipt.
type pluginApprovedDTO struct {
	ApprovalID string    `json:"approvalId"`
	Status     string    `json:"status"`
	ApprovedAt time.Time `json:"approvedAt"`
}

// asPlugins asks an agent's plugin approvals; an agent that serves none
// answers as one that does not know the id.
func asPlugins[T any](ask func(context.Context, PluginApprovals) (T, error)) func(context.Context, Agent) (T, error) {
	return func(ctx context.Context, a Agent) (T, error) {
		p, ok := a.(PluginApprovals)
		if !ok {
			var zero T
			return zero, agent.ErrNotThisAgent
		}
		return ask(ctx, p)
	}
}

func (s *Server) getPlugin(w http.ResponseWriter, r *http.Request) {
	id, ok := s.linkedID(w, r, approvalParam)
	if !ok {
		return
	}
	req, err := find(r.Context(), s, asPlugins(func(ctx context.Context, p PluginApprovals) (approval.PluginRequest, error) {
		return p.PluginApprovalRequest(ctx, id)
	}))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, req)
}

func (s *Server) postPlugin(w http.ResponseWriter, r *http.Request) {
	id, ok := s.linkedID(w, r, approvalParam)
	if !ok {
		return
	}
	body, ok := s.body(w, r, pageOnly)
	if !ok {
		return
	}
	// The body is the JSON the plugin approval code carries; parsing it as
	// that code reuses the code's strict decoding.
	resp, err := approval.ParsePluginResponse(approval.PluginResponsePrefix + passkey.Bytes(body).String())
	if err != nil || resp.ApprovalID != id {
		s.fail(w, &mcp.ToolError{Code: agent.CodeInvalidArgument, Message: "the body is not this plugin approval's signed response"})
		return
	}
	at, err := find(r.Context(), s, asPlugins(func(ctx context.Context, p PluginApprovals) (time.Time, error) {
		return p.RelayPluginApproval(ctx, resp)
	}))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.reply(w, pluginApprovedDTO{ApprovalID: id.String(), Status: "APPROVED", ApprovedAt: at.UTC()})
}

// issueLink issues a short link for the CLI, to a caller that shows proof
// of the item's binding text; a wrong proof is answered as an unknown id.
func (s *Server) issueLink(w http.ResponseWriter, r *http.Request, name string,
	issue func(context.Context, Agent, uuid.UUID, string) (string, error),
) {
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
	secret := r.Header.Get(links.SecretHeader)
	if !s.linkLive(id, secret) {
		s.fail(w, s.deadLink(id, secret))
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
	*mcp.ToolError
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
	agent.CodeQueryTimeout:          http.StatusGatewayTimeout,
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
	dto := errorDTO{
		Code: te.Code, Message: te.Message, Reason: te.Reason, PersonMessage: te.PersonMessage, NextSteps: personSteps(te.NextSteps),
	}
	var ne *nonceError
	if errors.As(err, &ne) {
		dto.RescopeNonce = ne.nonce
	}
	writeJSON(w, status, dto)
}

// errorDTO is the pages' error body: the contract's tool error as the page
// shows it, with the person's message and only the steps for the person.
type errorDTO struct {
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	Reason        string         `json:"reason,omitempty"`
	PersonMessage string         `json:"personMessage,omitempty"`
	NextSteps     []mcp.NextStep `json:"nextSteps,omitempty"`
	// RescopeNonce is set only on the 409 for a widened revert the engine
	// no longer holds: the nonce of the person's new widen proof.
	RescopeNonce passkey.Bytes `json:"rescopeNonce,omitempty"`
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
