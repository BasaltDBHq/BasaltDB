package setup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/strictjson"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// probeBackend reads the engine's own files: the probe's answers need no
// database.
type probeBackend struct{ testBackend }

func (probeBackend) Lstat(path string) error {
	_, err := os.Lstat(path)
	return err
}

// basalt init's probe is answered GUARD_UPDATED for an Update of its agent
// that finished after the init opened the link, to every such probe, and
// never for one that finished before, another agent's, or the empty probe
// of an init that has not opened a link. A "No" and a removal still come
// first.
func TestTheProbeAnswersAnUpdateOnlyAfterTheLinkOpened(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	s, err := NewLocal(LocalOptions{
		Backend: probeBackend{}, ConfigPath: path, Origin: "http://localhost:8787", Configured: true,
		Now:      func() time.Time { return now },
		Profiles: func() *trustprofile.Set { return trustprofile.NewSet(nil, nil, nil) },
	})
	require.NoError(t, err)
	ctx := context.Background()
	code := func(req Request) string {
		t.Helper()
		_, err := s.Check(ctx, req)
		require.Error(t, err)
		return AsRefusal(err).Code
	}
	probe := func(agent string, since time.Time) Request { return Request{Agent: agent, Since: &since} }

	// The probe's body, as basalt init sends it, is a setup request.
	var wire Request
	require.NoError(t, strictjson.Decode([]byte(`{"agent":"demo_bot","since":"2026-11-26T10:00:01.5Z"}`), &wire))
	require.Equal(t, "demo_bot", wire.Agent)
	require.True(t, wire.Since.Equal(now.Add(1500*time.Millisecond)))

	// An Update that finished before this init opened its link.
	s.markUpdated("demo_bot")
	opened := now.Add(time.Second)
	require.Equal(t, CodeJobUnavailable, code(probe("demo_bot", opened)), "a stale Update ends no init")
	require.Equal(t, CodeJobUnavailable, code(probe("demo_bot", now)), "an Update at the same instant is not after")

	now = now.Add(5 * time.Second)
	s.markUpdated("demo_bot")
	require.Equal(t, CodeGuardUpdated, code(probe("demo_bot", opened)))
	require.Equal(t, CodeGuardUpdated, code(probe("demo_bot", opened)), "not read once: a second init for the agent ends too")
	require.Equal(t, CodeJobUnavailable, code(probe("sales_bot", opened)), "another agent's init keeps waiting")
	require.Equal(t, CodeJobUnavailable, code(Request{}), "the empty probe is never GUARD_UPDATED")
	require.Equal(t, CodeJobUnavailable, code(Request{Agent: "demo_bot"}), "a probe without since is never GUARD_UPDATED")

	// A No comes first, read once, then the Update again.
	s.mark.at = now // what NotMine leaves

	require.Equal(t, CodeResetAsked, code(probe("demo_bot", opened)))
	require.Equal(t, CodeGuardUpdated, code(probe("demo_bot", opened)))

	// Since rides only on the probe.
	for _, job := range []string{JobUpdate, JobRemove, JobLabels} {
		req := probe("demo_bot", opened)
		req.Job = job
		require.Equal(t, CodeInvalidArgument, code(req), job)
	}

	// After a Remove deleted engine.json, every probe is ENGINE_REMOVED.
	require.NoError(t, os.Remove(path))
	require.Equal(t, CodeEngineRemoved, code(probe("demo_bot", opened)))
}

// A fix the page finished (a certificate, labels, a passkey, the agent's
// login) ends basalt init's wait like an Update: CHANGED_ and the fix's
// job, for a fix after the link opened, to every such probe, and never for
// one before it or for another agent.
func TestTheProbeAnswersAFixOnlyAfterTheLinkOpened(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	s, err := NewLocal(LocalOptions{
		Backend: probeBackend{}, ConfigPath: path, Origin: "http://localhost:8787", Configured: true,
		Now:      func() time.Time { return now },
		Profiles: func() *trustprofile.Set { return trustprofile.NewSet(nil, nil, nil) },
	})
	require.NoError(t, err)
	code := func(agent string, since time.Time) string {
		t.Helper()
		_, err := s.Check(context.Background(), Request{Agent: agent, Since: &since})
		require.Error(t, err)
		return AsRefusal(err).Code
	}
	s.markFixed("demo_bot", JobTrust)
	opened := now.Add(time.Second)
	require.Equal(t, CodeJobUnavailable, code("demo_bot", opened), "a fix before the link opened ends no init")
	require.Equal(t, CodeJobUnavailable, code("demo_bot", now), "a fix at the same instant is not after")

	now = now.Add(5 * time.Second)
	s.markFixed("demo_bot", JobTrust)
	require.Equal(t, CodeChangedPrefix+JobTrust, code("demo_bot", opened))
	require.Equal(t, CodeChangedPrefix+JobTrust, code("demo_bot", opened), "not read once")
	require.Equal(t, CodeJobUnavailable, code("sales_bot", opened), "another agent's init keeps waiting")
}
