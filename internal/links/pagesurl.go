package links

import "github.com/basaltdbhq/basaltdb/internal/config"

// CheckPagesURL refuses a --pages-url value that breaks the URL rule or
// has a query or fragment.
func CheckPagesURL(v string) error {
	return config.CheckPagesURL("--pages-url", v)
}
