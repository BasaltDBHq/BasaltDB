package supabase_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/supabase"
)

func TestPoolerHost(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"aws-0-eu-central-1.pooler.supabase.com": true,
		"aws-0-eu-central-1.pooler.supabase.co":  true,
		"AWS-0-X.Pooler.Supabase.CO":             true,
		"aws-0-x.pooler.supabase.co.":            true,
		"pooler.supabase.com":                    false,
		"evilpooler.supabase.com":                false,
		"aws-0-x.pooler.supabase.com.evil.test":  false,
		"aws-0-x.pooler.supabase.cod":            false,
		"db.abcdefghijklmnopqrst.supabase.co":    false,
		"":                                       false,
	} {
		require.Equal(t, want, supabase.PoolerHost(host), host)
	}
}
