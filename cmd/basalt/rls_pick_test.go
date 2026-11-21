package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRLSAnswers(t *testing.T) {
	t.Parallel()
	asks := []rlsAsk{{Table: "global.user_router", Rows: 7}, {Table: "us.activities", Rows: 53}, {Table: "us.transactions", Rows: 898}}
	runOwn := func(mode AgentRLSMode, quiet bool, stdin string, own []string) ([]bool, string, error) {
		var stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })
		got, err := rlsAnswers(c, mode, quiet, "bot", own, asks)
		return got, stderr.String(), err
	}

	run := func(mode AgentRLSMode, quiet bool, stdin string) ([]bool, string, error) {
		return runOwn(mode, quiet, stdin, nil)
	}
	t.Run("flag values", func(t *testing.T) {
		t.Parallel()
		got, _, err := run(AgentRLSAllRows, false, "")
		require.NoError(t, err)
		require.Equal(t, []bool{true, true, true}, got)
		got, _, err = run(AgentRLSNone, false, "")
		require.NoError(t, err)
		require.Equal(t, []bool{false, false, false}, got)
		got, _, err = run("us.*,global.user_router", false, "")
		require.NoError(t, err)
		require.Equal(t, []bool{true, true, true}, got)
		got, _, err = run("us.activities", true, "")
		require.NoError(t, err)
		require.Equal(t, []bool{false, true, false}, got, "a list applies with --yes")
	})

	t.Run("unknown entry is a usage error naming it", func(t *testing.T) {
		t.Parallel()
		_, _, err := run("us.nope", false, "")
		require.ErrorIs(t, err, errUsage)
		require.Contains(t, err.Error(), "us.nope")
	})

	t.Run("a re-run names tables that are no longer hidden", func(t *testing.T) {
		t.Parallel()
		got, _, err := runOwn("us.orders,us.activities", false, "", []string{"us.orders", "us.activities"})
		require.NoError(t, err)
		require.Equal(t, []bool{false, true, false}, got)
		_, _, err = runOwn("eu.orders", false, "", []string{"us.orders"})
		require.ErrorIs(t, err, errUsage)
	})

	t.Run("ask quiet says yes and names the tables", func(t *testing.T) {
		t.Parallel()
		got, errText, err := run(AgentRLSAsk, true, "none\n")
		require.NoError(t, err)
		require.Equal(t, []bool{true, true, true}, got)
		require.Contains(t, errText, "bot can see all rows of global.user_router, us.activities, us.transactions")
		require.Contains(t, errText, "--agent-rls=none")
	})

	t.Run("none quiet says no and prints nothing", func(t *testing.T) {
		t.Parallel()
		got, errText, err := run(AgentRLSNone, true, "")
		require.NoError(t, err)
		require.Equal(t, []bool{false, false, false}, got)
		require.Empty(t, errText)
	})

	t.Run("piped line", func(t *testing.T) {
		t.Parallel()
		for stdin, want := range map[string][]bool{
			"":                         {true, true, true},
			"\n":                       {true, true, true},
			"all\n":                    {true, true, true},
			"none\n":                   {false, false, false},
			"us.*\n":                   {false, true, true},
			"global.user_router,us.*":  {true, true, true},
			"us.transactions\nignored": {false, false, true},
		} {
			got, errText, err := run(AgentRLSAsk, false, stdin)
			require.NoError(t, err, stdin)
			require.Equal(t, want, got, stdin)
			require.Contains(t, errText, "us (2 tables, 951 rows)")
			require.Contains(t, errText, "us.activities  53 rows")
		}
		for _, bad := range []string{"yes\n", "us\n", "us.*,\n"} {
			_, _, err := run(AgentRLSAsk, false, bad)
			require.ErrorIs(t, err, errUsage, bad)
			require.Contains(t, err.Error(), "--agent-rls form")
		}
		_, _, err := run(AgentRLSAsk, false, "eu.*\n")
		require.ErrorIs(t, err, errUsage)
		require.Contains(t, err.Error(), "eu.*")
	})
}

func TestAgentRLSFlagValues(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"ask", "all-rows", "none", "us.*", "us.*,global.user_router"} {
		var m AgentRLSMode
		require.NoError(t, m.Set(ok), ok)
	}
	for _, bad := range []string{"", "some", "ALL_ROWS", "us", "us.*,"} {
		var m AgentRLSMode
		require.Error(t, m.Set(bad), bad)
	}
}
