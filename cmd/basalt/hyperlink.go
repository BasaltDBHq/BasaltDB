package main

import (
	"flag"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// pagesURLFlag registers --pages-url, which must follow the URL rule and
// have no query or fragment; a bad value is a usage error (exit 2).
func pagesURLFlag(fs *flag.FlagSet, dst *string, usage string) {
	fs.Func("pages-url", usage, func(v string) error {
		if err := checkPagesURL(v); err != nil {
			return err
		}
		*dst = v
		return nil
	})
}

func checkPagesURL(v string) error {
	return config.CheckPagesURL("--pages-url", v)
}
