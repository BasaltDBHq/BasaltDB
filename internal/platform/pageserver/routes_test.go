package pageserver_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setuppage"
	"github.com/basaltdbhq/basaltdb/web"
)

var updateRoutes = flag.Bool("update-routes", false, "rewrite testdata/routes.golden")

// probeAgent takes every link as live and answers every call with an
// error naming the call, so the route table golden shows which handler a
// request reached.
type probeAgent struct{}

var _ pageserver.PluginApprovals = probeAgent{}

func (probeAgent) ApprovalRequest(context.Context, uuid.UUID) (approval.Request, error) {
	return approval.Request{}, errors.New("ApprovalRequest")
}

func (probeAgent) RelayApproval(context.Context, approval.Response) (linksvc.Receipt, error) {
	return linksvc.Receipt{}, errors.New("RelayApproval")
}

func (probeAgent) RevertRequest(context.Context, uuid.UUID, string) (revert.Request, error) {
	return revert.Request{}, errors.New("RevertRequest")
}

func (probeAgent) RelayRevert(context.Context, revert.Response) (revertstore.AppliedRevert, linksvc.Receipt, error) {
	return revertstore.AppliedRevert{}, linksvc.Receipt{}, errors.New("RelayRevert")
}

func (probeAgent) RescopeRevert(context.Context, uuid.UUID, string, revertsvc.ScopeRequest) (revertsvc.ScopeResponse, error) {
	return revertsvc.ScopeResponse{}, errors.New("RescopeRevert")
}

func (probeAgent) RejectRevert(context.Context, uuid.UUID, string, revertsvc.RejectRequest) (revertsvc.RejectResponse, error) {
	return revertsvc.RejectResponse{}, errors.New("RejectRevert")
}

func (probeAgent) RevealApproval(context.Context, uuid.UUID, string, linksvc.RevealRequest) (approval.RevealAnswer, error) {
	return approval.RevealAnswer{}, errors.New("RevealApproval")
}

func (probeAgent) RevealRevert(context.Context, uuid.UUID, string, linksvc.RevealRequest) (approval.RevealAnswer, error) {
	return approval.RevealAnswer{}, errors.New("RevealRevert")
}

func (probeAgent) CheckLink(uuid.UUID, string) bool      { return true }
func (probeAgent) CheckResetLink(uuid.UUID, string) bool { return false }

func (probeAgent) PageFailure(err error) *toolresult.ToolError {
	return &toolresult.ToolError{Code: "PROBE", Message: err.Error()}
}

func (probeAgent) PluginApprovalRequest(context.Context, uuid.UUID) (approval.PluginRequest, error) {
	return approval.PluginRequest{}, errors.New("PluginApprovalRequest")
}

func (probeAgent) RelayPluginApproval(context.Context, approval.PluginApprovalResponse) (time.Time, error) {
	return time.Time{}, errors.New("RelayPluginApproval")
}

// probeID is the item every probe names.
var probeID = uuid.MustParse("01900000-0000-7000-8000-000000000001")

// apiProbes are the pages API routes, as the page calls them.
var apiProbes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/approvals/%s"},
	{http.MethodPost, "/api/v1/approvals/%s/approve"},
	{http.MethodPost, "/api/v1/approvals/%s/reveal"},
	{http.MethodGet, "/api/v1/reverts/%s"},
	{http.MethodPost, "/api/v1/reverts/%s/apply"},
	{http.MethodPost, "/api/v1/reverts/%s/scope"},
	{http.MethodPost, "/api/v1/reverts/%s/reject"},
	{http.MethodPost, "/api/v1/reverts/%s/reveal"},
	{http.MethodGet, "/api/v1/plugins/%s"},
	{http.MethodPost, "/api/v1/plugins/%s/approve"},
	{http.MethodPost, "/api/v1/plugins/%s/links"},
	{http.MethodPost, "/api/v1/links/%s"},
}

// setupProbes are the setup routes and the page.
var setupProbes = []string{
	pageserver.SetupCheckPath, pageserver.SetupRunPath, pageserver.SetupDoctorPath, pageserver.SetupEnginePath, pageserver.SetupNotMinePath,
}

// fileProbes are the pages, their files and what is not served.
var fileProbes = []string{
	"/healthz", "/setup/", "/setup/x", "/style.css", "/lib/codec.js", "/lib/x.css", "/fonts/OFL.txt", "/fonts/x.ttf",
	"/", "/index.html", "/home/index.html", "/approve/index.html", "/api/v1/", "/api/v1/home", "/approvals/x",
}

// probe is one request and what it got, as one golden line.
func probe(h http.Handler, method, path, origin, contentType, body string) string {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "localhost:8787"
	req.Header.Set(links.SecretHeader, "probe-secret")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return fmt.Sprintf("%s %s origin=%q type=%q body=%q -> %s", method, strings.ReplaceAll(path, probeID.String(), "{id}"),
		origin, contentType, body, answer(w.Code, w.Header(), w.Body.Bytes()))
}

func answer(status int, h http.Header, body []byte) string {
	b := strings.TrimSpace(string(body))
	if len(b) > 300 {
		b = fmt.Sprintf("%d bytes sha256:%x", len(body), sha256.Sum256(body))
	}
	return fmt.Sprintf("%d type=%q cache=%q allow=%q %s", status, h.Get("Content-Type"), h.Get("Cache-Control"), h.Get("Allow"), b)
}

// probeHandler runs every probe against h.
func probeHandler(h http.Handler) []string {
	var out []string
	for _, p := range apiProbes {
		for _, id := range []string{probeID.String(), "x"} {
			path := fmt.Sprintf(p.path, id)
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				out = append(out, probe(h, method, path, setupOrigin, "application/json", "{}"))
			}
		}
		path := fmt.Sprintf(p.path, probeID)
		out = append(out,
			probe(h, p.method, path, "https://other.example", "application/json", "{}"),
			probe(h, p.method, path, setupOrigin, "text/plain", "{}"),
			probe(h, p.method, path, setupOrigin, "application/json", `{"a":{"DatabaseURL":"x"}}`),
		)
	}
	for _, path := range setupProbes {
		out = append(out,
			probe(h, http.MethodGet, path, setupOrigin, "", ""),
			probe(h, http.MethodPost, path, setupOrigin, "application/json", "{}"),
			probe(h, http.MethodPost, path, "https://other.example", "application/json", "{}"),
			probe(h, http.MethodPost, path, setupOrigin, "application/json", `{"databaseUrl":"x"}`),
		)
	}
	for _, path := range fileProbes {
		out = append(out, probe(h, http.MethodGet, path, "", "", ""))
	}
	for _, r := range web.PageRoutes {
		path := r.Path
		if r.ID {
			out = append(out, probe(h, http.MethodGet, path+"x", "", "", ""))
			path += probeID.String()
		}
		out = append(out, probe(h, http.MethodGet, path, "", "", ""), probe(h, http.MethodPost, path, setupOrigin, "application/json", "{}"))
	}
	return out
}

// probeSession runs the API probes through a session on probeID's link.
func probeSession(t *testing.T, srv *pageserver.Server) []string {
	t.Helper()
	secrets := links.NewSecrets(time.Now, rand.Reader)
	secret, err := secrets.Issue(probeID, time.Now().Add(time.Hour))
	require.NoError(t, err)
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	link := pageserver.SessionLink{Token: keys.Token, Item: probeID}
	paths := make([]string, 0, len(apiProbes)+len(setupProbes)+2)
	for _, p := range apiProbes {
		paths = append(paths, fmt.Sprintf(p.path, probeID))
	}
	paths = append(paths, setupProbes...)
	paths = append(paths, "/healthz", "/", pageserver.HomeDataPath, "/approvals/"+probeID.String())
	out := make([]string, 0, 2*len(paths))
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			headers := map[string]string{links.SecretHeader: secret, "origin": setupOrigin, "content-type": "application/json"}
			got := srv.Dispatch(context.Background(), link, pageserver.SessionRequest{Method: method, Path: path, Headers: headers, Body: []byte("{}")})
			out = append(out, fmt.Sprintf("SESSION %s %s -> %s", method, strings.ReplaceAll(path, probeID.String(), "{id}"),
				answer(got.Status, http.Header{"Content-Type": {got.ContentType}}, got.Body)))
		}
	}
	return out
}

// TestRouteTable is the pages' route table as requests see it: every API
// route with its handler, method and path parameter, the setup routes of
// an engine with and without setup jobs and of one with no config, the
// page files, and the routes a session may reach.
func TestRouteTable(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	var got []string
	section := func(name string, lines []string) {
		got = append(got, "== "+name)
		got = append(got, lines...)
	}

	configured := newMounted(setupOrigin, log)
	configured.Add(probeAgent{})
	section("configured", probeHandler(configured.Handler()))

	withSetup := newMounted(setupOrigin, log)
	withSetup.Add(probeAgent{})
	withSetup.MountSetup(setuppage.NewSetupHandlers(setupOrigin, &fakeJobs{}, log.With("component", "setup")))
	section("with setup jobs", probeHandler(withSetup.Handler()))

	section("setup only", probeHandler(setuppage.SetupOnlyHandler(setupOrigin, &fakeJobs{}, log)))

	session := newMounted(setupOrigin, log)
	session.Add(probeAgent{})
	section("session", probeSession(t, session))

	golden := filepath.Join("testdata", "routes.golden")
	text := strings.Join(got, "\n") + "\n"
	if *updateRoutes {
		require.NoError(t, os.MkdirAll("testdata", 0o750))
		require.NoError(t, os.WriteFile(golden, []byte(text), 0o600))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err)
	require.Equal(t, string(want), text)
}
