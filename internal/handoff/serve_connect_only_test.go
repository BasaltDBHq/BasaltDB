package handoff_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

type stoppedFiles struct {
	exists     bool
	existsErr  error
	calls      []string
	confirmErr error
}

func (f *stoppedFiles) CredentialExists() (bool, error) { return f.exists, f.existsErr }
func (f *stoppedFiles) Lock() (func(), error) {
	f.calls = append(f.calls, "lock")
	return func() { f.calls = append(f.calls, "unlock") }, nil
}
func (f *stoppedFiles) RemoveSecret() error { f.calls = append(f.calls, "remove"); return nil }
func (f *stoppedFiles) ConfirmSetup(id string) error {
	f.calls = append(f.calls, "confirm "+id)
	return f.confirmErr
}

func TestServesConnectOnly(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	waitingSetup := func() *config.Setup {
		return &config.Setup{SetupID: "s1", Kind: "INSTALL", Code: "c", AwaitingAddress: true}
	}

	serves, err := handoff.ServesConnectOnly(nil, false, &stoppedFiles{}, log)
	require.NoError(t, err)
	require.False(t, serves, "no pending setup")

	f := &stoppedFiles{exists: true}
	serves, err = handoff.ServesConnectOnly(waitingSetup(), true, f, log)
	require.NoError(t, err)
	require.True(t, serves)
	require.Empty(t, f.calls, "as root nothing is touched")

	f = &stoppedFiles{}
	serves, err = handoff.ServesConnectOnly(waitingSetup(), false, f, log)
	require.NoError(t, err)
	require.True(t, serves, "waiting for the address")
	require.Empty(t, f.calls)

	f = &stoppedFiles{exists: true}
	serves, err = handoff.ServesConnectOnly(waitingSetup(), false, f, log)
	require.NoError(t, err)
	require.False(t, serves, "an interrupted YES is finished")
	require.Equal(t, []string{"lock", "remove", "confirm s1", "unlock"}, f.calls)

	_, err = handoff.ServesConnectOnly(waitingSetup(), false, &stoppedFiles{existsErr: errors.New("denied")}, log)
	require.EqualError(t, err, "denied")
	_, err = handoff.ServesConnectOnly(waitingSetup(), false, &stoppedFiles{exists: true, confirmErr: errors.New("locked")}, log)
	require.EqualError(t, err, "locked")
}
