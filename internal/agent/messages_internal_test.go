package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// TestPersonMessagesNameNoCommandWithALongConfigPath builds the
// personMessages that once offered a command named after --config, with a
// 252-character path: each stays within the limit and names no basalt
// command, since the person acts on a link (CONTRACT.md, Next steps).
func TestPersonMessagesNameNoCommandWithALongConfigPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a-long-directory-name-of-sixty-characters-in-total-ok-ok-ok-", 4) + "engine.json"
	s := newTestService(t, "linux", long)

	messages := map[string]string{}
	messages["not granted"] = s.notGrantedSteps(guidance.NewSteps(), notGrantedSplit{other: 12, otherNamespaces: 3, noun: agentstore.Noun{One: "schema", Many: "schemas"}})
	messages["describe not found"] = s.describeNotFoundSteps(guidance.NewSteps(), guidance.Failure{Tool: guidance.ToolDescribe})
	w, err := s.rlsWarning("public." + strings.Repeat("t", 60))
	require.NoError(t, err)
	messages["rls warning"] = w.PersonMessage

	for name, m := range messages {
		require.NoError(t, guidance.CheckPersonMessage(m), "%s: %s", name, m)
		require.NotContains(t, m, long, name)
		require.NotContains(t, m, "basalt ", "%s: the person runs no command", name)
	}
}

func TestDescribeNotFoundHintsAtAnotherAgent(t *testing.T) {
	t.Parallel()
	s := newTestService(t, "linux", "/etc/basalt-test/engine.json")
	msg := s.describeNotFoundSteps(guidance.NewSteps(), guidance.Failure{Tool: guidance.ToolDescribe})
	require.Contains(t, msg, "another database needs its own agent")
	require.NotContains(t, msg, "basalt ", "the person runs no command")
	require.NoError(t, guidance.CheckPersonMessage(msg))
}
