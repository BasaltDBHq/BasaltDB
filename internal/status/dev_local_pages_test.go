package status

import (
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

func TestDevLocalPagesStepIsTheAgentsInit(t *testing.T) {
	t.Parallel()
	cmds := guidance.NewCommands("bot", "", config.DefaultPath("linux"), "linux", osservice.Manager())
	b := guidance.NewSteps()
	person := devLocalPagesSteps(b, cmds.OperatedBy(mcpcontract.OperatedByAgent))
	steps, err := b.Build()
	require.NoError(t, err)
	require.Len(t, steps, 2)
	require.Equal(t, toolresult.ActionAskPerson, steps[0].Action)
	require.Equal(t, toolresult.NextStep{Actor: toolresult.ActorAgent, Action: toolresult.ActionRunCommand, Text: steps[1].Text, Command: "basalt init --agent bot --remote"}, steps[1])
	require.NotContains(t, person, "basalt ", "the person runs no command")
}
