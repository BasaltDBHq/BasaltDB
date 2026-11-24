package setupcli

import (
	"errors"
	"os/user"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

func TestAgentOSUserInTheEngineGroupIsRefused(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{"alice": {"20", "1001"}, "bob": {"20"}}
	lookupGroups := func(name string) ([]string, error) {
		g, ok := groups[name]
		if !ok {
			return nil, user.UnknownUserError(name)
		}
		return g, nil
	}
	engineGroup := func(name string) (*user.Group, error) {
		if name == "basalt" {
			return &user.Group{Gid: "1001", Name: "basalt"}, nil
		}
		return nil, user.UnknownGroupError(name)
	}

	err := checkAgentOSUserWith("alice", "basalt", engineGroup, lookupGroups)
	require.ErrorIs(t, err, cli.ErrUsage)
	require.ErrorContains(t, err, "--os-user alice is in the engine's group basalt")
	require.NoError(t, checkAgentOSUserWith("bob", "basalt", engineGroup, lookupGroups))
	require.ErrorContains(t, checkAgentOSUserWith("basalt", "basalt", engineGroup, lookupGroups), "the engine's own OS user")
	for _, reserved := range []string{"basalt-plugin-acme-ner-default", "_basalt-plugin-x"} {
		require.ErrorContains(t, checkAgentOSUserWith(reserved, "basalt", engineGroup, lookupGroups), "keeps those names for plugins")
	}

	// A first install: the engine's group does not exist yet, so no one is in it.
	require.NoError(t, checkAgentOSUserWith("alice", "_basalt", engineGroup, lookupGroups))

	// Anything that cannot be looked up refuses.
	broken := func(string) (*user.Group, error) { return nil, errors.New("nss down") }
	require.ErrorContains(t, checkAgentOSUserWith("alice", "basalt", broken, lookupGroups), "cannot be looked up")
	require.ErrorContains(t, checkAgentOSUserWith("carol", "basalt", engineGroup, lookupGroups), "cannot be read")
}
