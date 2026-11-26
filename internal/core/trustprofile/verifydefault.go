package trustprofile

import (
	"net/url"
	"strings"
)

// sslModeVerifyFull is the parameter VerifyFullByDefault adds.
const sslModeVerifyFull = "sslmode=verify-full"

// VerifyFullByDefault is dsn with sslmode=verify-full when it names no
// sslmode and its one host is one a built-in profile of set covers
// (Supabase, Amazon RDS): the provider's roots are known, so the
// certificate is checked without the person asking for it. The parameter
// is appended and the rest of the string kept byte for byte. Anything
// else is returned as given: an explicit sslmode (whatever its value), a
// string that names its own root (sslrootcert), a host no profile covers or
// one an operator's profile decides for (a pin, a replaced or disabled
// built-in), several hosts, a host parameter, a fragment, a key=value
// string or one that does not parse.
func VerifyFullByDefault(dsn string, set *Set) string {
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Fragment != "" || strings.Contains(dsn, "#") || strings.Contains(u.Host, ",") {
		return dsn
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Has("sslmode") || q.Has("sslrootcert") || q.Has("host") || q.Has("hostaddr") {
		return dsn
	}
	if p := set.For(u.Hostname()); p == nil || p.Origin != BuiltIn {
		return dsn
	}
	switch {
	case u.RawQuery != "":
		return dsn + "&" + sslModeVerifyFull
	case strings.HasSuffix(dsn, "?"):
		return dsn + sslModeVerifyFull
	}
	return dsn + "?" + sslModeVerifyFull
}
