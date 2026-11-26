package mcpcontract_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

var updatePageLimits = flag.Bool("update-page-limits", false, "rewrite pages/limits.json from the Go constants")

// pageLimitsFile holds the limits the pages enforce, from the engine's
// constants. web/lib/limits.test.mjs checks the pages against it.
const pageLimitsFile = "pages/limits.json"

type pageLimits struct {
	Approval  approvalLimits `json:"approval"`
	Revert    revertLimits   `json:"revert"`
	Links     linkLimits     `json:"links"`
	Passkey   passkeyLimits  `json:"passkey"`
	AgentName agentNameRule  `json:"agentName"`
}

type approvalLimits struct {
	MaxRows int `json:"maxRows"`
}

type revertLimits struct {
	MaxLines   int `json:"maxLines"`
	MaxBatch   int `json:"maxBatch"`
	ApplyHours int `json:"applyHours"`
}

type linkLimits struct {
	MaxFragmentLength int `json:"maxFragmentLength"`
	MaxInflatedBytes  int `json:"maxInflatedBytes"`
}

type passkeyLimits struct {
	ChallengeBytes int `json:"challengeBytes"`
	UserIDBytes    int `json:"userIdBytes"`
	MaxLabelBytes  int `json:"maxLabelBytes"`
}

// agentNameRule is the agent-name rule under the default prefix: its
// longest name, and names the engine accepts and refuses.
type agentNameRule struct {
	MaxLength int      `json:"maxLength"`
	Accepted  []string `json:"accepted"`
	Refused   []string `json:"refused"`
}

// agentNameProbes are names on both sides of the rule's edges.
var agentNameProbes = []string{
	"a", "agent", "agent_1", "a9", "a_", "z0_9",
	"", "1agent", "_agent", "Agent", "agent-1", "agent 1", "agent.1", "agént",
}

// largestAccepted is the largest n in 1..limit for which ok(n) holds, or 0.
func largestAccepted(limit int, ok func(n int) bool) int {
	best := 0
	for n := 1; n <= limit; n++ {
		if ok(n) {
			best = n
		}
	}
	return best
}

func pageLimitsFromGo(t *testing.T) pageLimits {
	t.Helper()
	challengeLen := largestAccepted(1024, func(n int) bool {
		_, err := passkey.RegistrationRequestFor(make([]byte, n), make([]byte, 16), "a", "a")
		return err == nil
	})
	userIDLen := largestAccepted(1024, func(n int) bool {
		_, err := passkey.RegistrationRequestFor(make([]byte, challengeLen), make([]byte, n), "a", "a")
		return err == nil
	})
	maxLabel := largestAccepted(1024, func(n int) bool {
		_, err := passkey.RegistrationRequestFor(make([]byte, challengeLen), make([]byte, userIDLen), strings.Repeat("a", n), "a")
		return err == nil
	})

	maxName := largestAccepted(1024, func(n int) bool { return guardmodel.ValidAgentName(strings.Repeat("a", n)) })
	rule := agentNameRule{MaxLength: maxName}
	for _, name := range append(slices.Clone(agentNameProbes), strings.Repeat("a", maxName), strings.Repeat("a", maxName+1)) {
		if guardmodel.ValidAgentName(name) {
			rule.Accepted = append(rule.Accepted, name)
		} else {
			rule.Refused = append(rule.Refused, name)
		}
	}

	return pageLimits{
		Approval: approvalLimits{MaxRows: approval.MaxRows},
		Revert: revertLimits{
			MaxLines: revert.MaxLines, MaxBatch: revert.MaxBatch,
			ApplyHours: int(revert.ApplyWindow.Hours()),
		},
		Links: linkLimits{MaxFragmentLength: linkcodec.MaxFragmentLen, MaxInflatedBytes: linkcodec.MaxInflatedBytes},
		Passkey: passkeyLimits{
			ChallengeBytes: challengeLen, UserIDBytes: userIDLen, MaxLabelBytes: maxLabel,
		},
		AgentName: rule,
	}
}

// TestPageLimitsMatchTheEngine checks the shared fixture against the Go
// constants (go test -run TestPageLimitsMatchTheEngine -update-page-limits
// rewrites it). The pages' node test checks web/lib against the same file.
func TestPageLimitsMatchTheEngine(t *testing.T) {
	t.Parallel()
	got := pageLimitsFromGo(t)
	// A role name is a Postgres identifier, at most 63 bytes; the agent's
	// role is the default prefix's agent prefix and the name.
	require.Equal(t, 63-len(guardmodel.Names{Prefix: guardmodel.DefaultPrefix}.AgentPrefix()), got.AgentName.MaxLength,
		"the longest agent name is what the default prefix leaves of 63 bytes")
	want, err := json.MarshalIndent(got, "", "  ")
	require.NoError(t, err)
	want = append(want, '\n')
	if *updatePageLimits {
		require.NoError(t, os.WriteFile(pageLimitsFile, want, 0o600))
	}
	have, err := os.ReadFile(pageLimitsFile)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, have),
		"%s differs from the Go constants; rewrite it with -update-page-limits and update web/lib to match:\n%s", pageLimitsFile, want)
}
