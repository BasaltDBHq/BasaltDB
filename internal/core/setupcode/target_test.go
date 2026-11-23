package setupcode

import (
	"bytes"
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
