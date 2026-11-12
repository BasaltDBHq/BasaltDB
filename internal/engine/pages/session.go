package pages

import (
	"bytes"
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// The pages API over a Vault link session (CONTRACT.md, Vault channel,
// Frames): the page's requests arrive decrypted from the session and go to
// the same handlers as on loopback, with the same checks, statuses and
// bodies. Postgres still verifies every passkey signature the relays
// carry; the session only replaces the transport.

// sessionRoute is a route a session may call: the method, the resource
// (approvals or reverts) and the action after the id ("" for the read).
type sessionRoute struct {
	method   string
	resource string
	action   string
	param    string
	serve    func(*Server, http.ResponseWriter, *http.Request)
}

// sessionRoutes are the only routes a session dispatches: never the links
// issuing routes, /healthz, the pages or their files. The revert reject
// route joins when the engine serves it (RS-2).
var sessionRoutes = []sessionRoute{
	{http.MethodGet, approvalsResource, "", approvalParam, (*Server).getApproval},
	{http.MethodPost, approvalsResource, "approve", approvalParam, (*Server).postApproval},
	{http.MethodGet, revertsResource, "", revertParam, (*Server).getRevert},
	{http.MethodPost, revertsResource, "apply", revertParam, (*Server).postRevert},
	{http.MethodPost, revertsResource, "scope", revertParam, (*Server).postScope},
}

// The resources of the pages API and the path parameters naming an
// approval and a revert.
const (
	approvalsResource = "approvals"
	revertsResource   = "reverts"
	approvalParam     = "approvalId"
	revertParam       = "revertId"
)

// sessionAPIPrefix starts every route a session may call.
const sessionAPIPrefix = "/api/v1/"

// sessionHeaders are the only request headers a session may send.
var sessionHeaders = map[string]string{
	links.SecretHeader: links.SecretHeader,
	"origin":           "Origin",
	"content-type":     "Content-Type",
}

// maxSessionHeader bounds one header value (frame-message.schema.json).
const maxSessionHeader = 1024

// matchSessionRoute finds method and path among sessionRoutes, with the
// path's id as written.
func matchSessionRoute(method, path string) (sessionRoute, string, bool) {
	rest, ok := strings.CutPrefix(path, sessionAPIPrefix)
	if !ok {
		return sessionRoute{}, "", false
	}
	// resource/id, or resource/id/action.
	const withAction = 3
	parts := strings.Split(rest, "/")
	if len(parts) < withAction-1 || len(parts) > withAction {
		return sessionRoute{}, "", false
	}
	action := ""
	if len(parts) == withAction {
		action = parts[withAction-1]
	}
	for _, r := range sessionRoutes {
		if r.method == method && r.resource == parts[0] && r.action == action {
			return r, parts[1], true
		}
	}
	return sessionRoute{}, "", false
}

// Dispatch answers one whole request of a session on link: the routes of
// the allowlist only, for the session's own item only, with the session's
// own link secret (its sha256 and its token both match), from the portal's
// origin. Anything else is answered as on loopback: an unknown route, item
// or secret as an unknown id (404 NOT_FOUND, one body for all), another
// header 400, a foreign origin 403, a body over 16 KiB 413.
func (s *Server) Dispatch(ctx context.Context, link vault.SessionLink, req vault.Request) vault.Response {
	w := newRecorder()
	s.serveSession(ctx, w, link, req)
	return w.response()
}

func (s *Server) serveSession(ctx context.Context, w http.ResponseWriter, link vault.SessionLink, req vault.Request) {
	route, id, ok := matchSessionRoute(req.Method, req.Path)
	if !ok {
		s.fail(w, unknownLink())
		return
	}
	for name, value := range req.Headers {
		if _, ok := sessionHeaders[name]; !ok || len(value) > maxSessionHeader {
			writeError(w, http.StatusBadRequest, agent.CodeInvalidArgument,
				"a request may carry only the basalt-link-secret, origin and content-type headers")
			return
		}
	}
	secret := req.Headers[links.SecretHeader]
	if id != link.Item.String() || !sessionSecret(secret, link.Token) {
		s.fail(w, unknownLink())
		return
	}
	if req.Headers["origin"] != s.origin {
		writeError(w, http.StatusForbidden, agent.CodePermissionDenied, "the request does not come from the approval page")
		return
	}
	if len(req.Body) > maxBody {
		writeError(w, http.StatusRequestEntityTooLarge, agent.CodeInvalidArgument, "the body is too large")
		return
	}
	r, err := http.NewRequestWithContext(ctx, req.Method, req.Path, bytes.NewReader(req.Body))
	if err != nil {
		s.fail(w, unknownLink())
		return
	}
	for name, value := range req.Headers {
		r.Header.Set(sessionHeaders[name], value)
	}
	r.SetPathValue(route.param, id)
	route.serve(s, w, r)
}

// sessionSecret reports whether secret is the session's own link's: its
// token derives to the session's. The handler then checks its sha256
// against the live link, as on loopback.
func sessionSecret(secret string, token channel.LinkToken) bool {
	keys, err := channel.DeriveLink(secret)
	if err != nil {
		return false
	}
	keys.PSK.Zero()
	return subtle.ConstantTimeCompare(keys.Token[:], token[:]) == 1
}

// recorder keeps a handler's response for the session.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder { return &recorder{header: http.Header{}} }

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) response() vault.Response {
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	return vault.Response{Status: status, ContentType: r.header.Get("Content-Type"), Body: r.body.Bytes()}
}
