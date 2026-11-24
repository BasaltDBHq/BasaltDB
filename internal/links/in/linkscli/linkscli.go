// Package linkscli is the links flags of the CLI.
package linkscli

import (
	"flag"

	"github.com/basaltdbhq/basaltdb/internal/links"
)

// PagesURLFlag registers --pages-url, which must follow the URL rule and
// have no query or fragment; a bad value is a usage error (exit 2).
func PagesURLFlag(fs *flag.FlagSet, dst *string, usage string) {
	fs.Func("pages-url", usage, func(v string) error {
		if err := links.CheckPagesURL(v); err != nil {
			return err
		}
		*dst = v
		return nil
	})
}
