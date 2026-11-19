package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

func TestPrintPlugins(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ps   []ledger.PluginHealth
		more int
		bad  string
		want string
	}{
		{name: "problem", bad: "boom", want: "Plugins: could not be read (boom)\n"},
		{
			name: "cut", more: 3,
			ps:   []ledger.PluginHealth{{Name: "a", Instance: "i", Version: "1", SignerKeyID: "k", Endpoint: "REMOTE", Host: "h:1"}},
			want: "Plugins: a/i 1 (signer k, REMOTE h:1); and 3 more\n",
		},
		{name: "no plugin event", ps: nil, want: ""},
		{name: "only disabled", ps: []ledger.PluginHealth{}, want: "Plugins: none\n"},
		{
			name: "local and remote",
			ps: []ledger.PluginHealth{
				{Name: "acme-ner", Instance: "default", Version: "1.4.0", SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Endpoint: "LOCAL", Files: "NONE", Network: "NOT_ENFORCED"},
				{Name: "acme-ner", Instance: "eu", Version: "1.5.0", SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Endpoint: "REMOTE", Host: "ner.acme.example:443"},
			},
			want: "Plugins: acme-ner/default 1.4.0 (signer jNZPxNG5htlwfhg4ZgknAA, LOCAL, files NONE, network NOT_ENFORCED); " +
				"acme-ner/eu 1.5.0 (signer jNZPxNG5htlwfhg4ZgknAA, REMOTE ner.acme.example:443)\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })
			printPlugins(c, ledger.Health{Plugins: tc.ps, PluginsMore: tc.more, PluginsProblem: tc.bad})
			require.Equal(t, tc.want, stderr.String())
		})
	}
}

// basalt log shows each plugin the agent's ledger records as served, with
// its version, signer, endpoint and isolation; a disabled one is gone.
func TestLogShowsThePluginsLine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err)
	defer conn.Close(ctx)

	r := cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, "Plugins:", "no plugin event, no line")

	local := guard.PluginDetail{
		Name: "acme-ner", Instance: "default", Version: "1.4.0", ManifestSHA256: strings.Repeat("ab", 32),
		SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Hooks: []string{"feed.observe"},
		Endpoint:  guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
		Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
	}
	remote := local
	remote.Instance, remote.Version, remote.Isolation = "eu", "1.5.0", nil
	remote.Endpoint = guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: "ner.acme.example:443"}
	remote.Egress = []string{"ner.acme.example:443"}
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, conn, guard.PluginEnabled, local))
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, conn, guard.PluginEnabled, remote))

	r = cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "Plugins: acme-ner/default 1.4.0 (signer jNZPxNG5htlwfhg4ZgknAA, LOCAL, files NONE, network NOT_ENFORCED); "+
		"acme-ner/eu 1.5.0 (signer jNZPxNG5htlwfhg4ZgknAA, REMOTE ner.acme.example:443)\n")

	require.NoError(t, guard.RecordPluginEntryEvent(ctx, conn, guard.PluginDisabled, local))
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, conn, guard.PluginDisabled, remote))
	r = cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "Plugins: none\n")
}

// The Plugins line lists at most ledger.MaxPluginsListed entries and says
// how many more there are.
func TestLogCapsThePluginsLine(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err)
	defer conn.Close(ctx)

	total := ledger.MaxPluginsListed + 3
	for i := range total {
		require.NoError(t, guard.RecordPluginEntryEvent(ctx, conn, guard.PluginEnabled, guard.PluginDetail{
			Name: fmt.Sprintf("p%03d", i), Instance: "default", Version: "1.0.0", ManifestSHA256: strings.Repeat("ab", 32),
			SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Hooks: []string{"feed.observe"},
			Endpoint: guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: "h.example:443"}, Egress: []string{"h.example:443"},
		}))
	}
	r := cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "p000/default")
	require.Contains(t, r.stderr, fmt.Sprintf("p%03d/default", ledger.MaxPluginsListed-1))
	require.NotContains(t, r.stderr, fmt.Sprintf("p%03d/default", ledger.MaxPluginsListed))
	require.Contains(t, r.stderr, "; and 3 more\n")
}
