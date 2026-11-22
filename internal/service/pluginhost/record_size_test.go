package plugin

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// withField is the local test manifest with one top-level field replaced.
func withField(t *testing.T, key string, value any) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(localManifest(), &m))
	m[key] = value
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

// A manifest whose ledger record the guard would refuse is refused at
// parse, so a plugin the person consents to can always be recorded.
func TestManifestMustFitItsLedgerRecord(t *testing.T) {
	t.Parallel()
	_, err := ParseManifest(withField(t, "version", "1.0.0-"+strings.Repeat("a", 58)))
	require.NoError(t, err, "64 bytes")
	_, err = ParseManifest(withField(t, "version", "1.0.0-"+strings.Repeat("a", 59)))
	require.ErrorContains(t, err, "at most 64 bytes")

	egress := make([]string, 0, maxEgress)
	for i := range maxEgress {
		egress = append(egress, fmt.Sprintf("%s%02d.example:443", strings.Repeat("h", 60), i))
	}
	_, err = ParseManifest(withField(t, "network", map[string]any{"egress": egress}))
	require.ErrorContains(t, err, "too large to record")
	_, err = ParseManifest(withField(t, "network", map[string]any{"egress": egress[:20]}))
	require.NoError(t, err)
}

// jsonbSpaces counts the separators Postgres pads, never those in strings.
func TestJSONBSpaces(t *testing.T) {
	t.Parallel()
	require.Equal(t, 4, jsonbSpaces([]byte(`{"a":"x:1,y","b":["c:2","d"]}`)))
	require.Equal(t, 1, jsonbSpaces([]byte(`{"a\":,":1}`)))
}
