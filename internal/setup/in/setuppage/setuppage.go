// Package setuppage serves the local setup page and its routes (CONTRACT.md,
// The local setup page): the only routes that read the admin connection
// string. app mounts its handlers on the page server, or serves
// SetupOnlyHandler on an engine with no config.
package setuppage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/web"
)

// setupPageFile is the setup page's file.
const setupPageFile = "setup/index.html"

// NewSetupHandlers serve the setup page's jobs for this engine's agents
// (CONTRACT.md, The local setup page), for Server.MountSetup: the only
// routes that read the admin connection string. origin is the page origin
// a POST must carry exactly.
func NewSetupHandlers(origin string, jobs SetupJobs, log *slog.Logger) pageserver.SetupHandlers {
	if origin == "" || jobs == nil || log == nil {
		panic("pages: origin, setup jobs and logger required")
	}
	st := setupRoutes{origin: origin, jobs: jobs, log: log}
	return pageserver.SetupHandlers{
		Page: serveSetupPage, Check: st.check, Run: st.run, Doctor: st.doctor, Engine: st.engine, NotMine: st.notMine,
	}
}

// NewConfiguredSetupHandlers are the setup routes of an engine with no
// setup jobs, for Server.MountSetup: every route refuses JOB_UNAVAILABLE
// without reading the body.
func NewConfiguredSetupHandlers(origin string) pageserver.SetupHandlers {
	c := configuredSetup{origin: origin}
	return pageserver.SetupHandlers{
		Page: serveSetupPage, Check: c.refuse, Run: c.refuse, Doctor: c.refuse, Engine: c.refuse, NotMine: c.refuse,
	}
}

// SetupJobs runs the setup page's jobs (setup.LocalService).
type SetupJobs interface {
	Check(ctx context.Context, req setup.Request) (setup.CheckAnswer, error)
	Run(ctx context.Context, req setup.Request) (setup.RunAnswer, error)
	Doctor(ctx context.Context, req setup.DoctorRequest) (setup.DoctorAnswer, error)
	Engine(ctx context.Context) (setup.EngineAnswer, error)
	NotMine(ctx context.Context) error
}

// SetupOnlyHandler is what an engine with no config serves: GET /healthz,
// the setup page with the files it loads, and the two setup routes, the
// only ones that read the admin connection string. origin is the page
// origin a POST must carry exactly.
func SetupOnlyHandler(origin string, jobs SetupJobs, log *slog.Logger) http.Handler {
	if origin == "" || jobs == nil || log == nil {
		panic("pages: origin, setup jobs and logger required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set(pageserver.BuildHeader, buildinfo.Version)
		_, _ = w.Write([]byte("ok\n"))
	})
	files := http.FileServerFS(web.Files)
	mux.Handle("GET /lib/{file}", pageserver.LibFile(files))
	mux.Handle("GET /style.css", files)
	mux.Handle("GET /fonts/{file}", pageserver.FontFile(files))
	mux.HandleFunc("GET "+pageserver.HomePath, pageserver.HomePage)
	mux.HandleFunc("GET "+pageserver.HomeDataPath, pageserver.HomeData(pageserver.NotSetUpHome{}))
	mux.HandleFunc("GET "+pageserver.SetupPagePath+"{$}", serveSetupPage)
	st := setupRoutes{origin: origin, jobs: jobs, log: log}
	mux.HandleFunc("POST "+pageserver.SetupCheckPath, st.check)
	mux.HandleFunc("POST "+pageserver.SetupRunPath, st.run)
	mux.HandleFunc("POST "+pageserver.SetupDoctorPath, st.doctor)
	mux.HandleFunc("POST "+pageserver.SetupEnginePath, st.engine)
	mux.HandleFunc("POST "+pageserver.SetupNotMinePath, st.notMine)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		pageserver.WriteError(w, http.StatusNotFound, "NOT_FOUND", "This engine has no config yet: it serves only its setup page.")
	})
	return mux
}

func serveSetupPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, web.Files, setupPageFile)
}

type setupRoutes struct {
	origin string
	jobs   SetupJobs
	log    *slog.Logger
}

func (st setupRoutes) check(w http.ResponseWriter, r *http.Request) {
	req, ok := st.request(w, r)
	if !ok {
		return
	}
	answer, err := st.jobs.Check(r.Context(), req)
	st.answer(w, answer, err, "check")
}

func (st setupRoutes) run(w http.ResponseWriter, r *http.Request) {
	req, ok := st.request(w, r)
	if !ok {
		return
	}
	answer, err := st.jobs.Run(r.Context(), req)
	if err == nil {
		st.log.Info("setup page: job ran", "job", req.Job, "agent", answer.Agent)
	}
	st.answer(w, answer, err, "run")
}

// request checks the Origin before it reads anything, then the content
// type, the size and the body's fields. The body is never logged.
// doctor is the Update check: the agent and its OS user, and never the
// admin string, which every route but check and run refuses.
func (st setupRoutes) doctor(w http.ResponseWriter, r *http.Request) {
	raw, ok := st.body(w, r)
	if !ok {
		return
	}
	if pageserver.HoldsDatabaseURL(raw) {
		pageserver.WriteError(w, http.StatusBadRequest, setup.CodeInvalidArgument, "This route never takes the admin connection string.")
		return
	}
	var req setup.DoctorRequest
	if !decodeStrict(raw, &req) {
		pageserver.WriteError(w, http.StatusBadRequest, setup.CodeInvalidArgument, "The body is not a setup request.")
		return
	}
	answer, err := st.jobs.Doctor(r.Context(), req)
	st.answer(w, answer, err, "doctor")
}

// decodeStrict decodes raw into v, refusing unknown fields and trailing
// data.
// engine answers what the engine is set up with, and notMine marks the
// person's "No, this isn't mine" for basalt init (CONTRACT.md, Not your
// database). Both take an empty object, never the admin string, and
// neither changes a file or a database.
func (st setupRoutes) engine(w http.ResponseWriter, r *http.Request) {
	if !st.empty(w, r) {
		return
	}
	answer, err := st.jobs.Engine(r.Context())
	st.answer(w, answer, err, "engine")
}

func (st setupRoutes) notMine(w http.ResponseWriter, r *http.Request) {
	if !st.empty(w, r) {
		return
	}
	err := st.jobs.NotMine(r.Context())
	if err == nil {
		st.log.Info("setup page: the person said the database is not theirs; basalt init asks for the administrator password")
	}
	st.answer(w, struct{}{}, err, "not-mine")
}

// empty reads a body that must be an empty JSON object.
func (st setupRoutes) empty(w http.ResponseWriter, r *http.Request) bool {
	raw, ok := st.body(w, r)
	if !ok {
		return false
	}
	if pageserver.HoldsDatabaseURL(raw) {
		pageserver.WriteError(w, http.StatusBadRequest, setup.CodeInvalidArgument, "This route never takes the admin connection string.")
		return false
	}
	var none struct{}
	if !decodeStrict(raw, &none) {
		pageserver.WriteError(w, http.StatusBadRequest, setup.CodeInvalidArgument, "This route takes an empty object.")
		return false
	}
	return true
}

func decodeStrict(raw []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && !dec.More()
}

func (st setupRoutes) request(w http.ResponseWriter, r *http.Request) (setup.Request, bool) {
	raw, ok := st.body(w, r)
	if !ok {
		return setup.Request{}, false
	}
	var req setup.Request
	if !decodeStrict(raw, &req) {
		pageserver.WriteError(w, http.StatusBadRequest, setup.CodeInvalidArgument, "The body is not a setup request.")
		return setup.Request{}, false
	}
	return req, true
}

// body checks the Origin and the content type, then reads the body up to
// the setup routes' limit.
func (st setupRoutes) body(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Header.Get("Origin") != st.origin {
		pageserver.WriteError(w, http.StatusForbidden, setup.CodeInvalidArgument, "The request does not come from the setup page.")
		return nil, false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		pageserver.WriteError(w, http.StatusUnsupportedMediaType, setup.CodeInvalidArgument, "The body must be application/json.")
		return nil, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, setupMaxBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		pageserver.WriteError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "The body is over 256 KiB.")
		return nil, false
	case err != nil:
		pageserver.WriteError(w, http.StatusBadRequest, setup.CodeInvalidArgument, "The body cannot be read.")
		return nil, false
	}
	return raw, true
}

func (st setupRoutes) answer(w http.ResponseWriter, answer any, err error, call string) {
	if err == nil {
		pageserver.WriteJSON(w, http.StatusOK, answer)
		return
	}
	ref := setup.AsRefusal(err)
	if c := ref.Cause; c != nil {
		// The cause is redacted where it is made: no connection string or
		// password (setup.Cause).
		st.log.Warn("setup page: refused", "call", call, "code", ref.Code, "step", c.Step, "sqlstate", c.SQLState, "cause", c.Message)
	} else {
		st.log.Info("setup page: refused", "call", call, "code", ref.Code)
	}
	pageserver.WriteJSON(w, setupStatus(ref), setupErrorDTO{ErrorDTO: pageserver.ErrorDTO{Code: ref.Code, Message: ref.Message}, TrustRoot: ref.TrustRoot, Pinned: ref.Pinned})
}

// setupErrorDTO is a setup refusal's body: the code and message, and on
// CERTIFICATE_NOT_VERIFIED the chain top the person may trust.
type setupErrorDTO struct {
	pageserver.ErrorDTO
	TrustRoot *setup.TrustRoot `json:"trustRoot,omitempty"`
	// Pinned is the SHA-256 pinned now, on a TRUST check's refusal of a
	// changed certificate.
	Pinned string `json:"pinned,omitempty"`
}

// setupStatus maps a refusal to its HTTP status (CONTRACT.md, The local
// setup page, Errors).
func setupStatus(r *setup.RefusalError) int {
	if r.Internal {
		return http.StatusInternalServerError
	}
	switch r.Code {
	case setup.CodeInvalidArgument, setup.CodeConnectionStringRefused, setup.CodeAnswersInvalid,
		setup.CodeChallengeExpired, setup.CodeChallengeInvalid, setup.CodePasskeyInvalid:
		return http.StatusBadRequest
	case setup.CodeDatabaseUnreachable:
		return http.StatusServiceUnavailable
	case setup.CodeTimeLimit:
		return http.StatusGatewayTimeout
	}
	return http.StatusConflict
}

// configuredSetup answers the setup routes of an engine that has a config:
// an install never changes it, and the body is never read.
type configuredSetup struct{ origin string }

func (c configuredSetup) refuse(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != c.origin {
		pageserver.WriteError(w, http.StatusForbidden, setup.CodeInvalidArgument, "The request does not come from the setup page.")
		return
	}
	pageserver.WriteError(w, http.StatusConflict, setup.CodeJobUnavailable,
		"This engine is already set up. An install never changes an engine that has a config; ask the agent for the setup link of the change you want.")
}

// setupMaxBody bounds the body of the two setup routes: an install of a real
// database sends up to 500 column labels. Every other route keeps maxBody.
const setupMaxBody = 256 << 10
