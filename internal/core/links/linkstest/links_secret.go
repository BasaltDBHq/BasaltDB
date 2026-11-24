package linkstest

import (
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// SecretOf is the secret a short link carries, or "".
func SecretOf(link string) string {
	_, frag, ok := strings.Cut(link, "#")
	if !ok {
		return ""
	}
	secret, _ := strings.CutPrefix(frag, links.SecretFragment)
	if secret == frag {
		return ""
	}
	return secret
}
