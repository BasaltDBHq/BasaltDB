package setupcode

import (
	"bytes"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewSetupID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 6, 2, 11, 987654321, time.UTC)
	id, expires, err := NewSetupID(now, bytes.NewReader(make([]byte, 16)))
	require.NoError(t, err)
	require.Regexp(t, setupIDPattern, id)
	require.Equal(t, "2026-11-12T06:12:11Z", expires)
	p := Payload{SetupID: id, ExpiresAt: expires}
	created, err := p.CreatedAt()
	require.NoError(t, err)
	require.Equal(t, now.Truncate(time.Millisecond), created)
	require.NoError(t, p.validateExpiry())
}

// TestTargetOfRefusesTargetParams: a connection URL whose query names the
// host, port or database is refused, naming the parameter.
func TestTargetOfRefusesTargetParams(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("postgres://app:pw@10.0.0.5/crm?dbname=other")
	require.NoError(t, err)
	_, err = TargetOf(u)
	require.ErrorContains(t, err, "dbname=")
	var pe *TargetParamError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "dbname", pe.Param)
}
