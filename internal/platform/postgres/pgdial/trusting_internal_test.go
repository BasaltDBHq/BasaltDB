package pgdial

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// The connection config of a Supabase host's string, as the hand-off probe
// and the engine open it, names the host for the certificate check and keeps
// verification on.
func TestConnConfigTrustingKeepsTheHostNameCheck(t *testing.T) {
	t.Parallel()
	const host = "db.abcdefghijklmnopqrst.supabase.co"
	ca, _ := trustprofiletest.Chain(t, host)
	cfg, err := connConfigTrusting("postgres://u:pw@"+host+":5432/postgres?sslmode=verify-full&channel_binding=require",
		trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}}))
	require.NoError(t, err)
	require.Equal(t, host, cfg.TLSConfig.ServerName)
	require.False(t, cfg.TLSConfig.InsecureSkipVerify)
}
