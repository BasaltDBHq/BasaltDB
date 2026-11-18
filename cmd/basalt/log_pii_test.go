package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// withoutPII drops the PII line and its warnings (guard version 15 and
// later) from basalt log's stderr.
func withoutPII(stderr string) string {
	var keep []string
	for _, line := range strings.SplitAfter(stderr, "\n") {
		if strings.HasPrefix(line, "PII: ") || strings.HasPrefix(line, "Plugins: ") || strings.Contains(line, "run basalt classify") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "")
}

func TestPrintPII(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	names := func(n int) []string {
		out := make([]string, 0, n)
		for i := range n {
			out = append(out, "public.t.c"+string(rune('a'+i)))
		}
		return out
	}
	for _, tc := range []struct {
		name string
		p    *ledger.PIIHealth
		want []string
		not  []string
	}{
		{name: "before version 15", p: nil},
		{
			name: "engine counts",
			p:    &ledger.PIIHealth{Classified: 7, Dictionary: &ledger.DictionaryHealth{Values: 1200, LastScanAt: &at}},
			want: []string{"PII: 7 columns classified, 0 unclassified; dictionary of 1200 values, last scan 2026-11-12T09:30:00Z\n"},
			not:  []string{"warning"},
		},
		{
			name: "not built yet, with warnings",
			p: &ledger.PIIHealth{
				Classified: 1, Unclassified: 12, UnclassifiedNames: names(ledger.MaxPIINames),
				Review: 2, ReviewNames: []string{"public.a.x", "public.b.y"},
			},
			want: []string{
				"PII: 1 columns classified, 12 unclassified; dictionary not built yet\n",
				"basalt: warning: 12 columns the agent can read are not classified yet: public.t.ca, public.t.cb, public.t.cc, public.t.cd, public.t.ce, public.t.cf, public.t.cg, public.t.ch, public.t.ci, public.t.cj, …; run basalt classify\n",
				"basalt: warning: 2 columns need a classification review (type changed or flagged): public.a.x, public.b.y; run basalt classify\n",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })
			printPII(c, tc.p, filepath.Join(t.TempDir(), "missing.json"))
			if tc.p == nil {
				require.Empty(t, stderr.String())
				return
			}
			for _, w := range tc.want {
				require.Contains(t, stderr.String(), w)
			}
			for _, n := range tc.not {
				require.NotContains(t, stderr.String(), n)
			}
		})
	}
}

func TestLogPrintsThePIILineFromStatusJSON(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	initAgent(t, d, cfgPath)
	registerTestPasskey(t, d)

	// The engine's state directory, named in the config, with its status.json.
	stateDir := filepath.Join(t.TempDir(), "state")
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(raw, &cfg))
	cfg["stateDir"] = stateDir
	raw, err = json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))

	r := cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "PII: 0 columns classified, 4 unclassified; dictionary not built yet\n")
	require.Contains(t, r.stderr, "basalt: warning: 4 columns the agent can read are not classified yet: public.leads.id, public.leads.name, public.leads.score, public.leads.status; run basalt classify")

	require.NoError(t, os.MkdirAll(filepath.Join(stateDir, pii.DictionaryDirName), 0o755))
	status := `{"dictionaryValues":40,"deltaValues":2,"fingerprintBits":32,"lastScanAt":"2026-11-12T08:00:00Z","lastScanColumns":3,"lastScanRows":20,"updatedAt":"2026-11-12T08:00:01Z"}`
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, pii.DictionaryDirName, pii.StatusFileName), []byte(status), 0o644))
	r = cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "PII: 0 columns classified, 4 unclassified; dictionary of 42 values, last scan 2026-11-12T08:00:00Z\n")
	require.True(t, strings.Index(r.stderr, "PII: ") < strings.Index(r.stderr, "basalt: warning:"), "the line comes before the warnings")
}
