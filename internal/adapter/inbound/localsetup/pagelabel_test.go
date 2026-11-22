package localsetup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/pages"
)

// unlabeled is the passkey as the setup page sends it: the browser's
// registration response and no label (the page asks for none).
func unlabeled(t *testing.T, c localsetup.Challenge) *localsetup.Passkey {
	t.Helper()
	p := register(t, c)
	p.Label = ""
	return p
}

// post sends body to path on h as the setup page does, and decodes the
// answer into out.
func post(t *testing.T, h http.Handler, path string, body any, out any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"label"`, "the page sends no passkey label")
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8787"+path, bytes.NewReader(raw))
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), out), w.Body.String())
	return w.Code
}

// The setup page's install sends the passkey with no label; the engine
// names it, and the install succeeds. Before, register_passkey refused
// the empty label (BS008 LEDGER_INPUT_INVALID, "label is required") and
// the run answered SETUP_FAILED.
func TestTheSetupPageInstallsWithAnUnlabeledPasskey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var logs bytes.Buffer
	h := pages.SetupOnlyHandler(origin, f.svc, slog.New(slog.NewTextHandler(&logs, nil)))

	var checked localsetup.CheckAnswer
	require.Equal(t, http.StatusOK, post(t, h, pages.SetupCheckPath, f.request(), &checked))
	require.True(t, checked.PasskeyNeeded)
	req := f.request()
	req.Challenge, req.Passkey = checked.Challenge, unlabeled(t, *checked.Challenge)
	var done localsetup.RunAnswer
	code := post(t, h, pages.SetupRunPath, req, &done)
	require.Equal(t, http.StatusOK, code, logs.String())
	require.Len(t, done.Passkeys, 1)
	require.NotEmpty(t, done.Passkeys[0].Label, "the engine names the passkey")

	var stored string
	require.NoError(t, f.db.Admin.QueryRow(context.Background(), `SELECT label FROM basalt_meta.passkeys`).Scan(&stored))
	require.Equal(t, done.Passkeys[0].Label, stored)
}

// The Update check's Add a passkey sends no label either.
func TestPasskeyAddWithAnUnlabeledPasskey(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	checked, err := svc.Check(ctx, f.fix(localsetup.JobPasskeyAdd))
	require.NoError(t, err)
	run := f.fix(localsetup.JobPasskeyAdd)
	run.Challenge, run.Passkey = checked.Challenge, unlabeled(t, *checked.Challenge)
	done, err := svc.Run(ctx, run)
	require.NoError(t, err)
	require.Len(t, done.Passkeys, 1)
	require.NotEmpty(t, done.Passkeys[0].Label)
}
