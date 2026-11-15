package setupcode_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

func TestCheckLocalEdges(t *testing.T) {
	t.Parallel()
	p := validPayload(t) // setupId time 2026-11-12T06:02:11Z, expires 24h later
	created, err := p.CreatedAt()
	require.NoError(t, err)
	expires, err := p.ExpiresTime()
	require.NoError(t, err)
	const binary = 16

	cases := map[string]struct {
		now     time.Time
		binary  int
		refusal setupcode.Refusal
	}{
		"just made":                     {created, binary, ""},
		"a second before expiry":        {expires.Add(-time.Second), binary, ""},
		"at expiry, no skew":            {expires, binary, setupcode.RefusalExpired},
		"setup id 5 minutes ahead":      {created.Add(-setupcode.ClockSkew), binary, ""},
		"setup id beyond the skew":      {created.Add(-setupcode.ClockSkew - time.Millisecond), binary, setupcode.RefusalSetupIDInFuture},
		"binary older than guard.to":    {created, binary - 1, setupcode.RefusalBinaryTooOld},
		"binary newer than guard.to ok": {created, binary + 1, ""},
	}
	old := p
	old.Guard.From, old.Guard.To = 0, setupcode.MinGuardVersion-1
	require.Equal(t, setupcode.RefusalGuardTooOld, refusalOf(t, setupcode.CheckLocal(old, created, binary)))
	require.ErrorContains(t, setupcode.CheckLocal(old, created, binary), "This setup code is for guard version 0, but setup codes need guard version 1 or later.")
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := setupcode.CheckLocal(p, c.now, c.binary)
			if c.refusal == "" {
				require.NoError(t, err)
				return
			}
			require.Equal(t, c.refusal, refusalOf(t, err))
		})
	}
}

// An expiresAt more than 24 hours and 5 minutes ahead of now cannot pass
// the codec (it is bound to the setupId's time) unless the setupId is also
// ahead: a setupId 4 minutes ahead and an expiry at its time plus 24 hours
// is fine, but CheckLocal is still the clock's word on its own.
func TestCheckLocalExpiryTooFar(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	created, err := p.CreatedAt()
	require.NoError(t, err)
	// The decoder already bounds expiresAt by the setupId; CheckLocal does
	// not trust that and checks the clock rule itself.
	p.ExpiresAt = created.Add(setupcode.Lifetime + setupcode.ClockSkew + time.Second).UTC().Format(time.RFC3339)
	err = setupcode.CheckLocal(p, created, 16)
	require.Equal(t, setupcode.RefusalExpiryTooFar, refusalOf(t, err))

	p.ExpiresAt = created.Add(setupcode.Lifetime + setupcode.ClockSkew).UTC().Format(time.RFC3339)
	require.NoError(t, setupcode.CheckLocal(p, created, 16))
}

func TestCheckLocalMessagesNameTheAgent(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	expires, err := p.ExpiresTime()
	require.NoError(t, err)
	err = setupcode.CheckLocal(p, expires, 16)
	require.EqualError(t, err, "This setup code expired on 2026-11-13 06:02 UTC. Ask lead_bot for a new one.")
}

func TestCheckDatabaseUsedBeforeSuperseded(t *testing.T) {
	t.Parallel()
	p := validPayload(t)
	newer := "01a1ffff-0000-7c3a-9f00-000000000000"
	db := setupcode.Database{
		Prefix: "basalt",
		Setups: []setupcode.RecordedSetup{
			{SetupID: newer, AgentRole: p.Role(), UsedAt: time.Now()},
			{SetupID: p.SetupID, AgentRole: p.Role(), UsedAt: time.Now()},
		},
	}
	require.Equal(t, setupcode.RefusalUsed, refusalOf(t, setupcode.CheckDatabase(p, db)))

	db.Setups = db.Setups[:1]
	require.Equal(t, setupcode.RefusalSuperseded, refusalOf(t, setupcode.CheckDatabase(p, db)))

	db.Setups[0].AgentRole = "basalt_agent_other"
	require.NoError(t, setupcode.CheckDatabase(p, db), "a newer setup of another agent does not matter")
}
