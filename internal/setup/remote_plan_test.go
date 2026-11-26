package setup

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// connectOnlyCode is a connect-only INSTALL code, as a run with no
// credential file makes it.
func connectOnlyCode(t *testing.T) string {
	t.Helper()
	plan, err := WithNewPassword(Plan{Kind: setupcode.KindInstall})
	require.NoError(t, err)
	run := RemoteRun{Agent: "bot", Prefix: guardmodel.DefaultPrefix, Timeout: guardmodel.DefaultRoleStatementTimeout, Latest: 12, ConnectOnly: true}
	p, err := run.Payload(plan, time.Now(), rand.Reader, nil, nil)
	require.NoError(t, err)
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	p.Engine = &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI())}
	p.Build = "1.0.0"
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	require.True(t, ConnectOnlyCode(code))
	return code
}

// Decide picks basalt init --remote's code from what the run found.
func TestRemoteRunDecide(t *testing.T) {
	t.Parallel()
	agent := &config.Agent{Name: "bot"}
	installing := &config.Agent{Name: "bot", Setup: &config.Setup{Kind: string(setupcode.KindInstall)}}
	// A connect-only code the person confirmed: no longer awaiting its
	// address, and not recorded in the database the agent logs in to.
	confirmed := &config.Agent{Name: "bot", Setup: &config.Setup{Kind: string(setupcode.KindInstall), Code: connectOnlyCode(t)}}
	for name, tc := range map[string]struct {
		run         RemoteRun
		kind        setupcode.Kind
		rotate      bool
		newPassword bool
		from        int
	}{
		"a changed certificate":        {run: RemoteRun{CertChanged: true, Entry: agent, Latest: 12}, kind: setupcode.KindUpgrade},
		"no login, no password":        {run: RemoteRun{Latest: 12}, kind: setupcode.KindInstall, rotate: true, newPassword: true},
		"no login, a password":         {run: RemoteRun{Entry: agent, Password: "pw", Latest: 12}, kind: setupcode.KindAgent, rotate: true, newPassword: true},
		"no login, an install pending": {run: RemoteRun{Entry: installing, Password: "pw", Latest: 12}, kind: setupcode.KindInstall, rotate: true},
		"logs in, a confirmed code not recorded": {
			run:  RemoteRun{LoggedIn: true, Entry: confirmed, Installed: 11, Latest: 12},
			kind: setupcode.KindAgent, rotate: true, newPassword: true, from: 11,
		},
		"logs in, not in the config":       {run: RemoteRun{LoggedIn: true, Installed: 12, Latest: 12}, kind: setupcode.KindAgent, from: 12},
		"logs in, an older guard":          {run: RemoteRun{LoggedIn: true, Entry: agent, Installed: 11, Latest: 12}, kind: setupcode.KindUpgrade, from: 11},
		"logs in, the guard is up to date": {run: RemoteRun{LoggedIn: true, Entry: agent, Installed: 12, Latest: 12}, kind: setupcode.KindAgent, from: 12},
	} {
		p, err := tc.run.Decide()
		require.NoError(t, err, name)
		require.Equal(t, tc.kind, p.Kind, name)
		require.Equal(t, tc.rotate, p.Rotate, name)
		require.Equal(t, tc.newPassword, p.NewPassword, name)
		require.Equal(t, tc.newPassword || tc.rotate, p.Password != "", name)
		require.Equal(t, tc.from, p.From, name)
		if name == "no login, an install pending" {
			require.Equal(t, "pw", p.Password, "the password this machine holds")
		}
	}
	_, err := RemoteRun{LoggedIn: true, Installed: 13, Latest: 12}.Decide()
	require.ErrorContains(t, err, "newer than this basalt")
}
