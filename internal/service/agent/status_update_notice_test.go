package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

func TestStatusCarriesTheUpdateWhenOneIsKnown(t *testing.T) {
	t.Parallel()
	status := func(update func() *ReleaseNotice) (guidance.StatusReport, *Service) {
		d := deps()
		d.Status.Update = update
		d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
		setApprovals(&d, keys{n: 1})
		d.Core.Now = func() time.Time { return statusNow }
		cmds, err := NewCommands("bot", "", "linux", testManager())
		require.NoError(t, err)
		d.Core.Commands = cmds
		s := NewService(d)
		r, err := s.Status(context.Background())
		require.NoError(t, err)
		return r, s
	}
	r, s := status(func() *ReleaseNotice {
		return &ReleaseNotice{Current: "0.0.1", Latest: "0.0.2", URL: "https://example.test/r"}
	})
	require.NotNil(t, r.Update)
	require.Equal(t, "0.0.2", r.Update.Latest)
	require.True(t, strings.HasPrefix(r.Update.Message, "WARNING: "), r.Update.Message)
	require.Equal(t, r.Update.Message, s.UpdateNotice())

	r, s = status(func() *ReleaseNotice { return nil })
	require.Nil(t, r.Update)
	require.Empty(t, s.UpdateNotice())
	r, _ = status(nil)
	require.Nil(t, r.Update)
}
