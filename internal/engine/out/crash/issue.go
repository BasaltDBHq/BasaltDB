package crash

import (
	"net/url"
	"sort"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// IssueBase is the new-issue page of the public repository.
const IssueBase = "https://github.com/BasaltDBHq/BasaltDB/issues/new"

// maxURL is the longest issue link built. GitHub refuses a request line
// past about 8 KB; this leaves room for proxies and terminals.
const maxURL = 6000

const trimmedNote = "...stack trimmed to fit the link; the full text is in the saved report..."

// Title is the issue title: the command and what happened.
func (rep Report) Title() string {
	what := "panic"
	if rep.Kind == servicespec.CrashKindFatal {
		what = "fatal error"
	}
	t := "crash(" + rep.Command + "): " + what
	if rep.ErrorCode != "" {
		t += " " + rep.ErrorCode
	}
	return t + " in " + rep.Version
}

// body is the issue text with stack as the stack's text.
func (rep Report) body(stack string) string {
	var b strings.Builder
	b.WriteString("Crash report " + rep.ID + ", saved by basalt. It holds the saved report and nothing else.\n\n")
	b.WriteString("| | |\n|---|---|\n")
	row := func(k, v string) {
		if v != "" {
			b.WriteString("| " + k + " | `" + strings.ReplaceAll(v, "`", "'") + "` |\n")
		}
	}
	row("version", rep.Version)
	row("os/arch", rep.OS+"/"+rep.Arch)
	row("go", rep.GoVersion)
	row("command", rep.Command)
	row("kind", rep.Kind)
	row("error code", rep.ErrorCode)
	row("time", rep.Time.Format("2006-01-02T15:04:05Z"))
	if rep.Message != "" {
		b.WriteString("\nMessage: `" + strings.ReplaceAll(rep.Message, "`", "'") + "`\n")
	}
	b.WriteString("\n```\n" + stack + "\n```\n")
	return b.String()
}

// IssueURL is the pre-filled new-issue link for the report. The stack is cut
// from the bottom (the top frames say where it crashed) until the whole link
// fits maxURL. Reports whether it was cut.
func (rep Report) IssueURL() (link string, trimmed bool) {
	link, trimmed, _ = rep.issueURL(maxURL)
	return link, trimmed
}

// IssueURLWithin is IssueURL for a link of at most limit characters (the
// status tool hands one over inside the link budget). When even the title,
// the fields and the note do not fit, it returns "" and ok false: no link is
// better than one over the budget.
func (rep Report) IssueURLWithin(limit int) (link string, trimmed, ok bool) {
	link, trimmed, ok = rep.issueURL(limit)
	if !ok {
		return "", false, false
	}
	return link, trimmed, true
}

// issueURL is the link of at most limit characters, or, when none fits, the
// shortest one with ok false.
func (rep Report) issueURL(limit int) (link string, trimmed, ok bool) {
	link = build(rep.Title(), rep.body(rep.Stack))
	if len(link) <= limit {
		return link, false, true
	}
	lines := strings.Split(rep.Stack, "\n")
	cut := func(n int) string {
		return build(rep.Title(), rep.body(strings.Join(lines[:n], "\n")+"\n"+trimmedNote))
	}
	// The longest prefix of the stack's lines that fits, with the note.
	n := sort.Search(len(lines), func(n int) bool { return len(cut(n+1)) > limit })
	link = cut(n)
	return link, true, len(link) <= limit
}

func build(title, body string) string {
	q := url.Values{"title": {title}, "body": {body}}
	return IssueBase + "?" + q.Encode()
}
