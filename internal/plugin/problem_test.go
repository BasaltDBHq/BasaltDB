package plugin

import (
	"errors"
	"os/user"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAgentUsersInEngineGroup: an agent whose OS user is in the engine's
// group, as primary or supplementary group, is refused by name; a lookup
// that fails refuses too.
func TestAgentUsersInEngineGroup(t *testing.T) {
	t.Parallel()
	groups := func(u string) ([]string, error) {
		switch u {
		case "alice":
			return []string{"20", "100"}, nil
		case "bob":
			return []string{"20"}, nil
		}
		return nil, errors.New("no such user")
	}
	require.NoError(t, checkAgentUsers("100", map[string]string{"product_b": "bob", "no_user": ""}, groups))

	err := checkAgentUsers("100", map[string]string{"product_a": "alice", "product_b": "bob"}, groups)
	var ge *AgentInGroupError
	require.ErrorAs(t, err, &ge)
	require.Equal(t, "product_a", ge.Agent)

	err = checkAgentUsers("100", map[string]string{"product_c": "carol"}, groups)
	require.ErrorIs(t, err, errGroupLookup)

	// The system lookup: the test's own user is in its own primary group.
	me, err := user.Current()
	require.NoError(t, err)
	g, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Skip("the test user's primary group has no name")
	}
	err = CheckAgentUsers(g.Name, map[string]string{"product_a": me.Username})
	require.ErrorAs(t, err, &ge)
	require.Equal(t, "product_a", ge.Agent)
	require.ErrorIs(t, CheckAgentUsers("basalt-test-no-such-group", map[string]string{"product_a": me.Username}), errGroupLookup)
}

// TestNotTrustedMessage: the problem names the entry and the failed check,
// and never another agent.
func TestNotTrustedMessage(t *testing.T) {
	t.Parallel()
	k := EntryKey{Name: "acme-ner", Instance: "client_x"}
	msg := NotTrustedMessage(k, &VerifyError{Reason: RefusedNotTrusted, File: "/p/bin/acme-ner", Why: "its SHA-256 is not the one the manifest states"}, "product_a")
	require.Equal(t, "plugin acme-ner/client_x was not started: /p/bin/acme-ner its SHA-256 is not the one the manifest states", msg)

	ge := &AgentInGroupError{Agent: "product_b"}
	require.Contains(t, NotTrustedMessage(k, ge, "product_b"), "this agent's OS user")
	other := NotTrustedMessage(k, ge, "product_a")
	require.Contains(t, other, "another agent's OS user")
	require.NotContains(t, other, "product_b")
	require.Equal(t, "PLUGIN_NOT_TRUSTED", ProblemNotTrusted)
}
