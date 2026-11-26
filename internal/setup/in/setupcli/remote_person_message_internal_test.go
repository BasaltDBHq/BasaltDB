//go:build unix

package setupcli

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// releasePage is where the person installs basalt on their own computer.
const releasePage = "https://github.com/BasaltDBHq/BasaltDB/releases"

func TestSetupPersonMessageFitsForTheLongestName(t *testing.T) {
	t.Parallel()
	name := ""
	for n := 1; n < 100; n++ {
		if candidate := strings.Repeat("a", n); config.ValidAgentName(candidate) {
			name = candidate
		}
	}
	require.GreaterOrEqual(t, len(name), 50)
	pm := setup.SetupPersonMessage(name, "3f9a 21c0 7d44 e1b2 90ac")
	withoutURL := strings.Replace(pm, releasePage+"\n", "", 1)
	require.LessOrEqual(t, utf8.RuneCountInString(withoutURL), guidance.MaxPersonMessageLength, pm)
	require.Equal(t, 1, strings.Count(pm, name), "the agent is named once")
}
