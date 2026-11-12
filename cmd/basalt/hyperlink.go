package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// OSC 8 hyperlink escapes (CONTRACT.md, Terminal hyperlinks). The URL rule
// keeps a URL from ending the sequence or starting another.
const (
	osc8Open  = "\x1b]8;;"
	osc8Mid   = "\x1b\\"
	osc8Close = "\x1b]8;;\x1b\\"
)

// linkRef says what a link belongs to, for the message when it is refused.
type linkRef struct {
	// setting is where the bad part came from (pagesUrl, --pages-url).
	setting string
	// item names the thing the link is for ("approval <id>").
	item string
	// again is the command that prints the link once the setting is fixed.
	again string
}

// isTerminal reports whether w is a terminal that takes OSC 8: a file that
// is a tty and TERM is not dumb.
func (c *cliIO) isTerminal(w io.Writer) bool {
	if c.tty != nil {
		return c.tty(w)
	}
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	return c.getenv("TERM") != "dumb"
}

// printLink writes link on a line of its own to w: an OSC 8 hyperlink on a
// terminal, the plain URL otherwise. A URL that breaks the URL rule is not
// written, in part or whole; the error names the setting, the item and the
// first bad character's position, never the byte.
func printLink(c *cliIO, w io.Writer, link string, ref linkRef) error {
	if err := links.CheckURL(link); err != nil {
		return refusedLink(err, ref)
	}
	if !c.isTerminal(w) {
		_, err := fmt.Fprintln(w, link)
		return err
	}
	_, err := fmt.Fprintln(w, osc8Open+link+osc8Mid+link+osc8Close)
	return err
}

func refusedLink(err error, ref linkRef) error {
	return fmt.Errorf("the link for %s is not printed: %w. It came from %s; fix %s, then run %s again",
		ref.item, err, ref.setting, ref.setting, ref.again)
}

// printableLabel replaces every control character, line break and
// non-ASCII byte of text from the database with "?", so it is safe in a
// message.
func printableLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r >= 0x7f {
			return '?'
		}
		return r
	}, s)
}

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
