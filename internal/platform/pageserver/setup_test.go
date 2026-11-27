package pageserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setuppage"
)

const setupOrigin = "http://localhost:8787"

// adminSecret is the admin password the requests below carry; no answer
// or log line may hold it.
const adminSecret = "hunter2-admin"

var adminString = "postgres://admin" + ":" + adminSecret + "@db.example:5432/app"

// fakeJobs records what reached the setup and answers with refusal, when
// set.
type fakeJobs struct {
	got     []setup.Request
	doctors []setup.DoctorRequest
	engines int
	notMine int
	// removeEngine counts the "Remove it from this computer too" presses.
	removeEngine int
	refusal      error
}

func (f *fakeJobs) Engine(context.Context) (setup.EngineAnswer, error) {
	f.engines++
	return setup.EngineAnswer{Agents: []string{"demo_bot"}, Databases: []setup.EngineDatabase{{Database: "app", Host: "db.example", Port: 5432}}}, f.refusal
}

func (f *fakeJobs) NotMine(context.Context) error {
	f.notMine++
	return f.refusal
}

func (f *fakeJobs) RemoveEngine(context.Context) error {
	f.removeEngine++
	return f.refusal
}

func (f *fakeJobs) Doctor(_ context.Context, req setup.DoctorRequest) (setup.DoctorAnswer, error) {
	f.doctors = append(f.doctors, req)
	return setup.DoctorAnswer{Database: "app"}, f.refusal
}

func (f *fakeJobs) Check(_ context.Context, req setup.Request) (setup.CheckAnswer, error) {
	f.got = append(f.got, req)
	return setup.CheckAnswer{Database: "app"}, f.refusal
}

func (f *fakeJobs) Run(_ context.Context, req setup.Request) (setup.RunAnswer, error) {
	f.got = append(f.got, req)
	return setup.RunAnswer{Agent: req.Agent}, f.refusal
}

type setupCall struct {
	path, origin, contentType, body string
}

func (c setupCall) do(h http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787"+c.path, strings.NewReader(c.body))
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	ct := c.contentType
	if ct == "" {
		ct = "application/json"
	}
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func setupBody(extra string) string {
	return `{"job":"INSTALL","agent":"demo_bot","osUser":"alice","demo":true,"databaseUrl":"` + adminString + `"` + extra + `}`
}

func TestSetupRoutesTakeTheAdminStringFromThePageOnly(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	jobs := &fakeJobs{}
	h := setuppage.SetupOnlyHandler(setupOrigin, jobs, slog.New(slog.NewTextHandler(&logs, nil)))

	for _, path := range []string{pageserver.SetupCheckPath, pageserver.SetupRunPath} {
		w := setupCall{path: path, origin: setupOrigin, body: setupBody("")}.do(h)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	}
	require.Len(t, jobs.got, 2)
	require.Equal(t, adminString, jobs.got[0].DatabaseURL)

	for _, v := range []struct {
		name string
		call setupCall
		code int
	}{
		{"no Origin", setupCall{path: pageserver.SetupCheckPath, body: setupBody("")}, http.StatusForbidden},
		{"a foreign Origin", setupCall{path: pageserver.SetupCheckPath, origin: "https://evil.example", body: setupBody("")}, http.StatusForbidden},
		{"the loopback address as Origin", setupCall{path: pageserver.SetupRunPath, origin: "http://127.0.0.1:8787", body: setupBody("")}, http.StatusForbidden},
		{"another port", setupCall{path: pageserver.SetupRunPath, origin: "http://localhost:8788", body: setupBody("")}, http.StatusForbidden},
		{"not JSON", setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, contentType: "text/plain", body: setupBody("")}, http.StatusUnsupportedMediaType},
		{"an unknown field", setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, body: setupBody(`,"extra":1`)}, http.StatusBadRequest},
		{"two bodies", setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, body: setupBody("") + "{}"}, http.StatusBadRequest},
		{"too large", setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, body: setupBody(`,"answers":[{"table":"` + strings.Repeat("x", 257<<10) + `"}]`)}, http.StatusRequestEntityTooLarge},
	} {
		w := v.call.do(h)
		require.Equal(t, v.code, w.Code, v.name)
		require.NotContains(t, w.Body.String(), adminSecret, v.name)
	}
	require.Len(t, jobs.got, 2, "no refused request reached the setup")

	// The setup routes take up to 256 KiB (500 column labels); the page's
	// other routes keep 16 KiB.
	big := setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, body: setupBody(`,"answers":[{"table":"` + strings.Repeat("x", 100<<10) + `"}]`)}.do(h)
	require.Equal(t, http.StatusOK, big.Code, big.Body.String())
	require.Len(t, jobs.got, 3)

	jobs.refusal = &setup.RefusalError{Code: setup.CodeLoginFailed, Message: "The database refused the login."}
	w := setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, body: setupBody("")}.do(h)
	require.Equal(t, http.StatusConflict, w.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, setup.CodeLoginFailed, body["code"])
	// A certificate the person may trust travels in the refusal's body.
	jobs.refusal = &setup.RefusalError{
		Code: setup.CodeCertificateNotVerified, Message: "not verified",
		TrustRoot: &setup.TrustRoot{Subject: "CN=Root", SHA256: strings.Repeat("a", 64), ExpiresAt: "2030-01-01T00:00:00Z"},
	}
	w = setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, body: setupBody("")}.do(h)
	var withRoot struct {
		Code      string
		TrustRoot setup.TrustRoot
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &withRoot))
	require.Equal(t, setup.CodeCertificateNotVerified, withRoot.Code)
	require.Equal(t, "CN=Root", withRoot.TrustRoot.Subject)
	require.Equal(t, strings.Repeat("a", 64), withRoot.TrustRoot.SHA256)
	require.NotContains(t, logs.String(), adminSecret, "the body is never logged")
	require.NotContains(t, logs.String(), "db.example")
}

func TestSetupRefusalStatuses(t *testing.T) {
	t.Parallel()
	for code, status := range map[string]int{
		setup.CodeInvalidArgument:         http.StatusBadRequest,
		setup.CodeConnectionStringRefused: http.StatusBadRequest,
		setup.CodeChallengeExpired:        http.StatusBadRequest,
		setup.CodeJobUnavailable:          http.StatusConflict,
		setup.CodeBusy:                    http.StatusConflict,
		setup.CodeRoleExists:              http.StatusConflict,
		setup.CodePasskeyRequired:         http.StatusConflict,
		setup.CodeDatabaseUnreachable:     http.StatusServiceUnavailable,
		setup.CodeTimeLimit:               http.StatusGatewayTimeout,
	} {
		jobs := &fakeJobs{refusal: &setup.RefusalError{Code: code, Message: "m"}}
		h := setuppage.SetupOnlyHandler(setupOrigin, jobs, slog.New(slog.DiscardHandler))
		w := setupCall{path: pageserver.SetupRunPath, origin: setupOrigin, body: setupBody("")}.do(h)
		require.Equal(t, status, w.Code, code)
	}
}

func TestSetupOnlyHandlerServesThePageAndNothingElse(t *testing.T) {
	t.Parallel()
	h := setuppage.SetupOnlyHandler(setupOrigin, &fakeJobs{}, slog.New(slog.DiscardHandler))
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787"+path, nil))
		return w
	}
	w := get("/setup/")
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Set up BasaltDB")
	require.Equal(t, http.StatusOK, get("/lib/setup.js").Code)
	require.Equal(t, http.StatusOK, get("/style.css").Code)
	require.Equal(t, http.StatusOK, get("/healthz").Code)
	// The root is the home page of an engine with no config.
	require.Equal(t, http.StatusOK, get("/").Code)
	home := get(pageserver.HomeDataPath)
	require.Equal(t, http.StatusOK, home.Code)
	require.Contains(t, home.Body.String(), `"state":"NOT_SET_UP"`)
	require.Contains(t, home.Body.String(), `"agents":0`)
	for _, path := range []string{"/approvals/" + uuid.NewString(), "/register/", "/lib/setup.test.mjs", "/setup/index.html.bak"} {
		require.Equal(t, http.StatusNotFound, get(path).Code, path)
	}
}

// On an engine that has a config, the setup routes run no install and read
// no body, and every other route refuses a body with a databaseUrl.
func TestConfiguredPagesTakeNoAdminString(t *testing.T) {
	t.Parallel()
	h := newMounted(setupOrigin, slog.New(slog.DiscardHandler)).Handler()
	w := setupCall{path: pageserver.SetupRunPath, origin: setupOrigin, body: setupBody("")}.do(h)
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), setup.CodeJobUnavailable)

	for _, path := range []string{
		"/api/v1/approvals/" + uuid.NewString() + "/approve",
		"/api/v1/reverts/" + uuid.NewString() + "/apply",
		"/api/v1/plugins/" + uuid.NewString() + "/approve",
	} {
		for _, body := range []string{
			`{"databaseUrl":"x"}`, `{"a":[{"b":{"databaseUrl":"x"}}]}`, `{"DatabaseURL":"x"}`, `{"databaseurl":"x"}`,
			`{"pad":"` + strings.Repeat("x", 17<<10) + `","databaseUrl":"x"}`,
		} {
			w := setupCall{path: path, origin: setupOrigin, body: body}.do(h)
			require.Equal(t, http.StatusBadRequest, w.Code, path)
			raw, err := io.ReadAll(w.Body)
			require.NoError(t, err)
			require.Contains(t, string(raw), "never takes the admin connection string", path)
		}
		w := setupCall{path: path, origin: setupOrigin, body: `{"approvalId":"x"}`}.do(h)
		require.NotEqual(t, http.StatusBadRequest, w.Code, "a body without one reaches the route: %s", path)
		w = setupCall{path: path, origin: "https://evil.example", body: `{"databaseUrl":"x"}`}.do(h)
		require.NotEqual(t, http.StatusBadRequest, w.Code, "a foreign Origin's body is not read here; the route and the listener refuse it: %s", path)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/setup/", nil))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestConfiguredPagesRunTheSetupJobsTheyAreGiven(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	jobs := &fakeJobs{}
	log := slog.New(slog.NewTextHandler(&logs, nil))
	srv := newMounted(setupOrigin, log)
	srv.MountSetup(setuppage.NewSetupHandlers(setupOrigin, jobs, log.With("component", "setup")))
	h := srv.Handler()
	body := `{"job":"UPDATE","agent":"demo_bot","osUser":"alice","demo":false,"databaseUrl":"` + adminString + `"}`

	for _, path := range []string{pageserver.SetupCheckPath, pageserver.SetupRunPath} {
		w := setupCall{path: path, origin: setupOrigin, body: body}.do(h)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotContains(t, w.Body.String(), adminSecret)
		w = setupCall{path: path, origin: "http://localhost:9999", body: body}.do(h)
		require.Equal(t, http.StatusForbidden, w.Code, "a foreign Origin is refused before the body is read")
	}
	require.Len(t, jobs.got, 2)
	require.Equal(t, "UPDATE", jobs.got[0].Job)
	require.Equal(t, adminString, jobs.got[1].DatabaseURL)
	require.NotContains(t, logs.String(), adminSecret)
	require.Contains(t, logs.String(), "job=UPDATE")

	// Every other route still refuses the admin string.
	w := setupCall{path: "/api/v1/approvals/" + uuid.NewString() + "/approve", origin: setupOrigin, body: body}.do(h)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// The Update check takes the agent and its OS user, never the admin
// string, on both handlers; an engine with no setup jobs refuses it.
func TestDoctorRouteTakesNoAdminString(t *testing.T) {
	t.Parallel()
	jobs := &fakeJobs{}
	srv := newMounted(setupOrigin, slog.New(slog.DiscardHandler))
	srv.MountSetup(setuppage.NewSetupHandlers(setupOrigin, jobs, slog.New(slog.DiscardHandler)))
	for _, h := range []http.Handler{srv.Handler(), setuppage.SetupOnlyHandler(setupOrigin, jobs, slog.New(slog.DiscardHandler))} {
		w := setupCall{path: pageserver.SetupDoctorPath, origin: setupOrigin, body: `{"agent":"demo_bot","osUser":"alice"}`}.do(h)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), `"database":"app"`)
		for _, body := range []string{`{"agent":"demo_bot","osUser":"alice","databaseUrl":"` + adminString + `"}`, `{"agent":"a","osUser":"b","extra":1}`} {
			w = setupCall{path: pageserver.SetupDoctorPath, origin: setupOrigin, body: body}.do(h)
			require.Equal(t, http.StatusBadRequest, w.Code, body)
			require.NotContains(t, w.Body.String(), adminSecret)
		}
		w = setupCall{path: pageserver.SetupDoctorPath, origin: "http://localhost:9999", body: `{"agent":"demo_bot","osUser":"alice"}`}.do(h)
		require.Equal(t, http.StatusForbidden, w.Code)
	}
	require.Len(t, jobs.doctors, 2)
	require.Equal(t, setup.DoctorRequest{Agent: "demo_bot", OSUser: "alice"}, jobs.doctors[0])

	h := newMounted(setupOrigin, slog.New(slog.DiscardHandler)).Handler()
	w := setupCall{path: pageserver.SetupDoctorPath, origin: setupOrigin, body: `{"agent":"demo_bot","osUser":"alice"}`}.do(h)
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), setup.CodeJobUnavailable)
}

// The engine check and the "No" take an empty object, never the admin
// string, on both handlers; an engine with no setup jobs refuses them. No
// route resets anything: a forged request to one is not found.
func TestNotYourDatabaseRoutesTakeNothing(t *testing.T) {
	t.Parallel()
	jobs := &fakeJobs{}
	srv := newMounted(setupOrigin, slog.New(slog.DiscardHandler))
	srv.MountSetup(setuppage.NewSetupHandlers(setupOrigin, jobs, slog.New(slog.DiscardHandler)))
	for _, h := range []http.Handler{srv.Handler(), setuppage.SetupOnlyHandler(setupOrigin, jobs, slog.New(slog.DiscardHandler))} {
		w := setupCall{path: pageserver.SetupEnginePath, origin: setupOrigin, body: `{}`}.do(h)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), `"database":"app"`)
		w = setupCall{path: pageserver.SetupNotMinePath, origin: setupOrigin, body: `{}`}.do(h)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		for _, path := range []string{pageserver.SetupEnginePath, pageserver.SetupNotMinePath} {
			for _, body := range []string{`{"databaseUrl":"` + adminString + `"}`, `{"run":true}`, `{"agent":"demo_bot"}`} {
				w = setupCall{path: path, origin: setupOrigin, body: body}.do(h)
				require.Equal(t, http.StatusBadRequest, w.Code, body)
				require.NotContains(t, w.Body.String(), adminSecret)
			}
			w = setupCall{path: path, origin: "http://localhost:9999", body: `{}`}.do(h)
			require.Equal(t, http.StatusForbidden, w.Code)
		}
		for _, path := range []string{"/api/v1/setup/reset", "/api/v1/setup/forget"} {
			w = setupCall{path: path, origin: setupOrigin, body: `{"run":true}`}.do(h)
			require.Equal(t, http.StatusNotFound, w.Code, path)
		}
	}
	require.Equal(t, 2, jobs.engines)
	require.Equal(t, 2, jobs.notMine)

	h := newMounted(setupOrigin, slog.New(slog.DiscardHandler)).Handler()
	for _, path := range []string{pageserver.SetupEnginePath, pageserver.SetupNotMinePath} {
		w := setupCall{path: path, origin: setupOrigin, body: `{}`}.do(h)
		require.Equal(t, http.StatusConflict, w.Code)
		require.Contains(t, w.Body.String(), setup.CodeJobUnavailable)
	}
}

// A TRUST check's refusal of a changed certificate carries the pin.
func TestSetupRefusalCarriesThePinnedCertificate(t *testing.T) {
	t.Parallel()
	jobs := &fakeJobs{refusal: &setup.RefusalError{
		Code: setup.CodeCertificateNotVerified, Message: "m", Pinned: strings.Repeat("b", 64),
		TrustRoot: &setup.TrustRoot{Subject: "CN=x", SHA256: strings.Repeat("a", 64), ExpiresAt: "2030-01-01T00:00:00Z"},
	}}
	h := setuppage.SetupOnlyHandler(setupOrigin, jobs, slog.New(slog.DiscardHandler))
	w := setupCall{path: pageserver.SetupCheckPath, origin: setupOrigin, body: setupBody("")}.do(h)
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), `"pinned":"`+strings.Repeat("b", 64)+`"`)
	require.Contains(t, w.Body.String(), `"sha256":"`+strings.Repeat("a", 64)+`"`)
}

// A SETUP_FAILED's cause reaches the engine's log (step, SQLSTATE and the
// redacted message) and never the person's answer; the request's admin
// string reaches neither.
func TestSetupFailedLogsItsCause(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	jobs := &fakeJobs{refusal: &setup.RefusalError{
		Code: setup.CodeSetupFailed, Message: "Reading the database or running the setup failed (Postgres error 42P01, install script, statement 3); nothing changed.",
		Cause: &setup.Cause{Step: "install script, statement 3", SQLState: "42P01", Message: `relation "basalt_meta.installs" does not exist`},
	}}
	h := setuppage.SetupOnlyHandler(setupOrigin, jobs, slog.New(slog.NewTextHandler(&logs, nil)))
	w := setupCall{path: pageserver.SetupRunPath, origin: setupOrigin, body: setupBody("")}.do(h)
	require.Equal(t, http.StatusConflict, w.Code)
	require.NotContains(t, w.Body.String(), "does not exist", "the cause stays in the log")
	line := logs.String()
	require.Contains(t, line, "code=SETUP_FAILED")
	require.Contains(t, line, "sqlstate=42P01")
	require.Contains(t, line, `step="install script, statement 3"`)
	require.Contains(t, line, `basalt_meta.installs`)
	require.NotContains(t, line, adminSecret)
	require.NotContains(t, line, "db.example")
}
