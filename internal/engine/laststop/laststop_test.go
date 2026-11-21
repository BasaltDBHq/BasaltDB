package laststop

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHashEngineJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(path, []byte("{\"mode\":\"SAME_USER\"}\n"), 0o600))

	sum := HashEngineJSON(path)
	require.Len(t, sum, 64)
	require.Equal(t, sum, HashEngineJSON(path), "stable")
	require.NotEqual(t, sum, HashEngineJSON(path+"-missing"))
	require.Empty(t, HashEngineJSON(""))
	require.Empty(t, HashEngineJSON(filepath.Join(dir, "gone.json")))

	require.NoError(t, os.WriteFile(path, []byte("{\"mode\":\"SAME_USER\"}\n "), 0o600))
	require.NotEqual(t, sum, HashEngineJSON(path), "a byte change changes the hash")
}

func TestStartHoldOffUntil(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(path, []byte("one\n"), 0o600))
	at := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	rec := LastStopFileRecord{Reason: "the engine crashed 5 times within 10s", At: at, EngineSHA256: HashEngineJSON(path)}

	_, ok := StartHoldOffUntil(rec, path, at.Add(-time.Second))
	require.False(t, ok, "before the give-up is not a hold-off")

	until, ok := StartHoldOffUntil(rec, path, at)
	require.True(t, ok)
	require.Equal(t, at.Add(time.Minute), until)

	until, ok = StartHoldOffUntil(rec, path, at.Add(30*time.Second))
	require.True(t, ok)
	require.Equal(t, at.Add(time.Minute), until)

	_, ok = StartHoldOffUntil(rec, path, at.Add(time.Minute))
	require.False(t, ok, "the hold-off ends at one minute")
	_, ok = StartHoldOffUntil(rec, path, at.Add(time.Minute+time.Second))
	require.False(t, ok)

	require.NoError(t, os.WriteFile(path, []byte("two\n"), 0o600))
	_, ok = StartHoldOffUntil(rec, path, at.Add(30*time.Second))
	require.False(t, ok, "a changed engine.json ends the hold-off")

	// A missing current file cannot confirm a change: the hold-off stands.
	_, ok = StartHoldOffUntil(rec, filepath.Join(dir, "gone.json"), at.Add(30*time.Second))
	require.True(t, ok)
	// An older record without a hash holds off on at alone.
	old := LastStopFileRecord{Reason: rec.Reason, At: at}
	until, ok = StartHoldOffUntil(old, path, at.Add(30*time.Second))
	require.True(t, ok)
	require.Equal(t, at.Add(time.Minute), until)
}
