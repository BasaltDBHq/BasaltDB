package agent

import (
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// The link budget (CONTRACT.md, Showing links). What the engine hands an
// agent as the way to open a page, in this order:
//
//  1. a short link, when one exists (the engine's local pages today; the
//     portal's short link over the Vault later, which only changes what the
//     caller passes as short);
//  2. else the long link, when it is at most the budget;
//  3. else the long link, over budget: the interim hand-over of owner
//     decision VC-28, with a warning in front of it.

// linkKind says which of the three the engine handed over.
type linkKind int

const (
	// linkShort is a short link: never measured.
	linkShort linkKind = iota + 1
	// linkLong is a long link within the budget.
	linkLong
	// linkOverBudget is a long link over the budget, handed over because
	// nothing else opens the page (VC-28).
	linkOverBudget
)

// handOver is the link the engine hands over and which of the three it is.
type handOver struct {
	URL  string
	Kind linkKind
}

// chooseLink picks the link to hand over: short when it is not empty, else
// long, measured in characters of the whole URL (every link is ASCII) against
// budget.
func chooseLink(short, long string, budget int) handOver {
	switch {
	case short != "":
		return handOver{URL: short, Kind: linkShort}
	case len(long) <= budget:
		return handOver{URL: long, Kind: linkLong}
	}
	return handOver{URL: long, Kind: linkOverBudget}
}

// Labels of links next to a personMessage: what opening the link does
// (api/mcp/links/link.schema.json).
const (
	labelApprove = "Approve the held write"
	labelRevert  = "Review and sign the revert"
)

// overBudgetWarning is the first line of a message that hands over an
// over-budget long link (VC-28).
const overBudgetWarning = "Warning: this link is long and may arrive cut or broken."

// Limits that keep what the agent supplies, and what the database names,
// from pushing a message over its 500 characters.
const (
	maxHeadlineChars = 100
	maxIntentChars   = 80
)

// messageBuilder composes a personMessage and its links (CONTRACT.md, Links
// in personMessage): text lines separated by \n, and each URL a paragraph of
// its own with an empty line before and after it.
type messageBuilder struct {
	blocks []messageBlock
	links  []mcp.Link
}

type messageBlock struct {
	text  string
	isURL bool
}

func newMessage() *messageBuilder { return &messageBuilder{} }

// Text adds a line of plain text.
func (m *messageBuilder) Text(line string) *messageBuilder {
	last := len(m.blocks) - 1
	if last >= 0 && !m.blocks[last].isURL {
		m.blocks[last].text += "\n" + line
		return m
	}
	m.blocks = append(m.blocks, messageBlock{text: line})
	return m
}

// Link adds url as a paragraph of its own and its label to links.
func (m *messageBuilder) Link(label, url string) *messageBuilder {
	m.blocks = append(m.blocks, messageBlock{text: url, isURL: true})
	m.links = append(m.links, mcp.Link{Label: label, URL: url})
	return m
}

// Build returns the message and its links, nil when it holds no URL.
func (m *messageBuilder) Build() (string, []mcp.Link) {
	parts := make([]string, 0, len(m.blocks))
	for _, b := range m.blocks {
		parts = append(parts, b.text)
	}
	return strings.Join(parts, "\n\n"), m.links
}

// Full-width ASCII forms (U+FF01 to U+FF5E) fold to ASCII, so a full-width
// colon or slash cannot dodge the strip below.
const (
	fullWidthFirst rune = 0xff01
	fullWidthLast  rune = 0xff5e
	fullWidthShift rune = 0xfee0
)

// linkLike is what makes text look like a link or hold a link fragment: a
// scheme separator, "www.", and the fragment prefixes of the link formats.
var linkLike = regexp.MustCompile(`(?i)(:?//|www\.|#1\.|#2\.|#s=)`)

// plainText makes text from the agent or the database safe inside a line of
// a personMessage: one line, no format or control character, full-width
// forms folded, and nothing that reads as a URL or a link fragment (a URL in
// a message is a link the engine hands over, on a line of its own).
func plainText(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.In(r, unicode.Cf, unicode.Cc):
			return -1
		case r >= fullWidthFirst && r <= fullWidthLast:
			return r - fullWidthShift
		}
		return r
	}, s)
	// Strip until stable: removing one match can join the pieces of another.
	for prev := ""; prev != s; {
		prev = s
		s = linkLike.ReplaceAllString(s, " ")
	}
	return strings.Join(strings.Fields(s), " ")
}

// clip shortens s to at most n characters, ending in "..." when it cuts.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-len(ellipsis)])) + ellipsis
}

// ellipsis ends a clipped text.
const ellipsis = "..."

// shown is text from the agent or the database as it appears in a message.
func shown(s string, n int) string { return clip(plainText(s), n) }

// approvalMessage is the personMessage of a held write at the link handed
// over: lead says what happened, tail lines follow the link. An over-budget
// link comes after a warning and the command (VC-28).
func approvalMessage(lead string, pick handOver, command string, tail ...string) (string, []mcp.Link) {
	msg := newMessage()
	switch pick.Kind {
	case linkOverBudget:
		msg.Text(overBudgetWarning).Text("Run this instead: " + command).Text(lead).Text("The whole link:")
	case linkLong:
		msg.Text(lead).Text("Approve it with your passkey here; the page then shows a code for the agent:")
	default:
		msg.Text(lead).Text("Approve it with your passkey here:")
	}
	msg.Link(labelApprove, pick.URL)
	if pick.Kind != linkOverBudget {
		msg.Text("Or run: " + command)
	}
	for _, line := range tail {
		msg.Text(line)
	}
	return msg.Build()
}

// revertMessage is the personMessage of a prepared revert at the link handed
// over: what it restores, why, and when it expires, then the link. An
// over-budget link comes after a warning only: a revert has no command to
// offer in its place (VC-28).
func revertMessage(summary string, pick handOver, extra ...string) (string, []mcp.Link) {
	msg := newMessage()
	if pick.Kind == linkOverBudget {
		msg.Text(overBudgetWarning)
	}
	msg.Text(summary)
	for _, line := range extra {
		msg.Text(line)
	}
	sign := "Sign it with your passkey here:"
	if pick.Kind != linkShort {
		sign = "Sign it with your passkey here; the page then shows a code for the agent:"
	}
	return msg.Text(sign).Link(labelRevert, pick.URL).Build()
}

// expiryLine states a deadline for a person.
func expiryLine(t time.Time) string { return "Expires " + t.UTC().Format(personTime) + "." }
