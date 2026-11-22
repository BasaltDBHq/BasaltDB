package pages

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/localsetup"
	"github.com/basaltdbhq/basaltdb/web"
)

// Setup paths (CONTRACT.md, The local setup page).
const (
	SetupPagePath  = "/setup/"
	SetupCheckPath = "/api/v1/setup/check"
	SetupRunPath   = "/api/v1/setup/run"
	// SetupDoctorPath is the Update check: no admin string.
	SetupDoctorPath  = "/api/v1/setup/doctor"
	SetupEnginePath  = "/api/v1/setup/engine"
	SetupNotMinePath = "/api/v1/setup/not-mine"
	setupPageFile    = "setup/index.html"
)

// SetupJobs runs the setup page's jobs (localsetup.Service).
type SetupJobs interface {
	Check(ctx context.Context, req localsetup.Request) (localsetup.CheckAnswer, error)
	Run(ctx context.Context, req localsetup.Request) (localsetup.RunAnswer, error)
	Doctor(ctx context.Context, req localsetup.DoctorRequest) (localsetup.DoctorAnswer, error)
	Engine(ctx context.Context) (localsetup.EngineAnswer, error)
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
		_, _ = w.Write([]byte("ok\n"))
	})
	files := http.FileServerFS(web.Files)
	mux.Handle("GET /lib/{file}", libFile(files))
	mux.Handle("GET /style.css", files)
	mux.Handle("GET /fonts/{file}", fontFile(files))
	mux.HandleFunc("GET "+SetupPagePath+"{$}", serveSetupPage)
	st := setupRoutes{origin: origin, jobs: jobs, log: log}
	mux.HandleFunc("POST "+SetupCheckPath, st.check)
	mux.HandleFunc("POST "+SetupRunPath, st.run)
	mux.HandleFunc("POST "+SetupDoctorPath, st.doctor)
	mux.HandleFunc("POST "+SetupEnginePath, st.engine)
	mux.HandleFunc("POST "+SetupNotMinePath, st.notMine)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "This engine has no config yet: it serves only its setup page.")
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
	if holdsDatabaseURL(raw) {
		writeError(w, http.StatusBadRequest, localsetup.CodeInvalidArgument, "This route never takes the admin connection string.")
		return
	}
	var req localsetup.DoctorRequest
	if !decodeStrict(raw, &req) {
		writeError(w, http.StatusBadRequest, localsetup.CodeInvalidArgument, "The body is not a setup request.")
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
	if holdsDatabaseURL(raw) {
		writeError(w, http.StatusBadRequest, localsetup.CodeInvalidArgument, "This route never takes the admin connection string.")
		return false
	}
	var none struct{}
	if !decodeStrict(raw, &none) {
		writeError(w, http.StatusBadRequest, localsetup.CodeInvalidArgument, "This route takes an empty object.")
		return false
	}
	return true
}

func decodeStrict(raw []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && !dec.More()
}

func (st setupRoutes) request(w http.ResponseWriter, r *http.Request) (localsetup.Request, bool) {
	raw, ok := st.body(w, r)
	if !ok {
		return localsetup.Request{}, false
	}
	var req localsetup.Request
	if !decodeStrict(raw, &req) {
		writeError(w, http.StatusBadRequest, localsetup.CodeInvalidArgument, "The body is not a setup request.")
		return localsetup.Request{}, false
	}
	return req, true
}

// body checks the Origin and the content type, then reads the body up to
// the setup routes' limit.
func (st setupRoutes) body(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Header.Get("Origin") != st.origin {
		writeError(w, http.StatusForbidden, localsetup.CodeInvalidArgument, "The request does not come from the setup page.")
		return nil, false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, localsetup.CodeInvalidArgument, "The body must be application/json.")
		return nil, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, setupMaxBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "The body is over 256 KiB.")
		return nil, false
	case err != nil:
		writeError(w, http.StatusBadRequest, localsetup.CodeInvalidArgument, "The body cannot be read.")
		return nil, false
	}
	return raw, true
}

func (st setupRoutes) answer(w http.ResponseWriter, answer any, err error, call string) {
	if err == nil {
		writeJSON(w, http.StatusOK, answer)
		return
	}
	ref := localsetup.AsRefusal(err)
	st.log.Info("setup page: refused", "call", call, "code", ref.Code)
	writeJSON(w, setupStatus(ref), setupErrorDTO{errorDTO: errorDTO{Code: ref.Code, Message: ref.Message}, TrustRoot: ref.TrustRoot, Pinned: ref.Pinned})
}

// setupErrorDTO is a setup refusal's body: the code and message, and on
// CERTIFICATE_NOT_VERIFIED the chain top the person may trust.
type setupErrorDTO struct {
	errorDTO
	TrustRoot *localsetup.TrustRoot `json:"trustRoot,omitempty"`
	// Pinned is the SHA-256 pinned now, on a TRUST check's refusal of a
	// changed certificate.
	Pinned string `json:"pinned,omitempty"`
}

// setupStatus maps a refusal to its HTTP status (CONTRACT.md, The local
// setup page, Errors).
func setupStatus(r *localsetup.RefusalError) int {
	if r.Status != 0 {
		return r.Status
	}
	switch r.Code {
	case localsetup.CodeInvalidArgument, localsetup.CodeConnectionStringRefused, localsetup.CodeAnswersInvalid,
		localsetup.CodeChallengeExpired, localsetup.CodeChallengeInvalid, localsetup.CodePasskeyInvalid:
		return http.StatusBadRequest
	case localsetup.CodeDatabaseUnreachable:
		return http.StatusServiceUnavailable
	case localsetup.CodeTimeLimit:
		return http.StatusGatewayTimeout
	}
	return http.StatusConflict
}

// configuredSetup answers the setup routes of an engine that has a config:
// an install never changes it, and the body is never read.
func (s *Server) configuredSetup(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.origin {
		writeError(w, http.StatusForbidden, localsetup.CodeInvalidArgument, "The request does not come from the setup page.")
		return
	}
	writeError(w, http.StatusConflict, localsetup.CodeJobUnavailable,
		"This engine is already set up. An install never changes an engine that has a config; ask the agent for the setup link of the change you want.")
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
			writeError(w, http.StatusBadRequest, localsetup.CodeInvalidArgument, "This route never takes the admin connection string.")
			return
		}
		r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(head), r.Body), Closer: r.Body}
		next.ServeHTTP(w, r)
	})
}

// setupMaxBody bounds the body of the two setup routes: an install of a real
// database sends up to 500 column labels. Every other route keeps maxBody.
const setupMaxBody = 256 << 10

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
	return holdsDatabaseURL(head)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// holdsDatabaseURL reports whether a JSON body has a databaseUrl field at
// any depth: only the setup routes take the admin connection string.
func holdsDatabaseURL(body []byte) bool {
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
