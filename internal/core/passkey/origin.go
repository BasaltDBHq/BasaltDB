package passkey

import "net/url"

// OnPagesOrigin keeps the passkeys registered on the origin of the pages at
// base, and returns that origin. A passkey signs only on the origin it was
// registered on, so a localhost one cannot sign an agent's portal links. A
// base with no origin keeps every passkey.
func OnPagesOrigin(keys []Credential, base string) ([]Credential, string) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return keys, ""
	}
	origin := u.Scheme + "://" + u.Host
	out := make([]Credential, 0, len(keys))
	for _, k := range keys {
		if k.Relying.Origin == origin {
			out = append(out, k)
		}
	}
	return out, origin
}
