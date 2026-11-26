package osservice_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// basalt init's probe is an empty request until it opened a CHANGE link,
// then one that names the agent and when; it returns the code answered.
func TestSetupStateSendsTheProbeItNames(t *testing.T) {
	t.Parallel()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"GUARD_UPDATED","message":"x"}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	code, err := osservice.SetupState(ctx, srv.URL, "/check", "", time.Time{})
	require.NoError(t, err)
	require.Equal(t, "GUARD_UPDATED", code)
	since := time.Date(2026, 11, 26, 10, 0, 0, 123456789, time.UTC)
	_, err = osservice.SetupState(ctx, srv.URL, "/check", "demo_bot", since)
	require.NoError(t, err)
	require.Equal(t, "{}", bodies[0])
	var got struct {
		Agent string    `json:"agent"`
		Since time.Time `json:"since"`
	}
	require.NoError(t, json.Unmarshal([]byte(bodies[1]), &got))
	require.Equal(t, "demo_bot", got.Agent)
	require.True(t, since.Equal(got.Since), "since keeps its nanoseconds")
	require.JSONEq(t, `{"agent":"demo_bot","since":"2026-11-26T10:00:00.123456789Z"}`, bodies[1])
}
