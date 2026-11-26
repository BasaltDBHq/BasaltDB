package setup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// Decide picks basalt init --remote's code from what the run found.
func TestRemoteRunDecide(t *testing.T) {
	t.Parallel()
	agent := &config.Agent{Name: "bot"}
	installing := &config.Agent{Name: "bot", Setup: &config.Setup{Kind: string(setupcode.KindInstall)}}
	for name, tc := range map[string]struct {
		run         RemoteRun
		kind        setupcode.Kind
		newPassword bool
		from        int
	}{
		"a changed certificate":            {run: RemoteRun{CertChanged: true, Entry: agent, Latest: 12}, kind: setupcode.KindUpgrade},
		"no login, no password":            {run: RemoteRun{Latest: 12}, kind: setupcode.KindInstall, newPassword: true},
		"no login, a password":             {run: RemoteRun{Entry: agent, Password: "pw", Latest: 12}, kind: setupcode.KindAgent, newPassword: true},
		"no login, an install pending":     {run: RemoteRun{Entry: installing, Password: "pw", Latest: 12}, kind: setupcode.KindInstall},
		"logs in, not in the config":       {run: RemoteRun{LoggedIn: true, Installed: 12, Latest: 12}, kind: setupcode.KindAgent, from: 12},
		"logs in, an older guard":          {run: RemoteRun{LoggedIn: true, Entry: agent, Installed: 11, Latest: 12}, kind: setupcode.KindUpgrade, from: 11},
		"logs in, the guard is up to date": {run: RemoteRun{LoggedIn: true, Entry: agent, Installed: 12, Latest: 12}, kind: setupcode.KindAgent, from: 12},
	} {
		p, err := tc.run.Decide()
		require.NoError(t, err, name)
		require.Equal(t, tc.kind, p.Kind, name)
		require.Equal(t, tc.newPassword, p.NewPassword, name)
		require.Equal(t, tc.from, p.From, name)
		if name == "no login, an install pending" {
			require.Equal(t, "pw", p.Password, "the password this machine holds")
		}
	}
	_, err := RemoteRun{LoggedIn: true, Installed: 13, Latest: 12}.Decide()
	require.ErrorContains(t, err, "newer than this basalt")
}
