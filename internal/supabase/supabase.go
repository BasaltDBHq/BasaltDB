// Package supabase knows the host names of Supabase's Postgres pooler.
package supabase

import "strings"

// poolerSuffixes are the host suffixes of Supabase's pooler (Supavisor):
// its certificate names both *.pooler.supabase.com and
// *.pooler.supabase.co.
var poolerSuffixes = []string{".pooler.supabase.com", ".pooler.supabase.co"}

// PoolerHost reports whether host is one of Supabase's pooler hosts, which
// route a connection by the project ref after the role name (user
// "postgres.<ref>" logs in as role postgres of project <ref>) and offer no
// channel binding. The match is on a label boundary, in any case, with or
// without a trailing dot: aws-0-x.pooler.supabase.co is one,
// evilpooler.supabase.com and pooler.supabase.com are not.
func PoolerHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, s := range poolerSuffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}
