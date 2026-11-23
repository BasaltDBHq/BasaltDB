package guidance

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// MessageBuilder composes a personMessage and its links (CONTRACT.md, Links
// in personMessage): text lines separated by \n, and each URL a paragraph of
// its own with an empty line before and after it.
type MessageBuilder struct {
	blocks []MessageBlock
	links  []toolresult.Link
}

// MessageBlock is one line of a person message: text, or a link with a label.
type MessageBlock struct {
	text  string
	isURL bool
}

// NewMessage starts an empty personMessage.
func NewMessage() *MessageBuilder { return &MessageBuilder{} }

// Text adds a line of plain text.
func (m *MessageBuilder) Text(line string) *MessageBuilder {
	last := len(m.blocks) - 1
	if last >= 0 && !m.blocks[last].isURL {
		m.blocks[last].text += "\n" + line
		return m
	}
	m.blocks = append(m.blocks, MessageBlock{text: line})
	return m
}

// Link adds url as a paragraph of its own and its label to links.
func (m *MessageBuilder) Link(label, url string) *MessageBuilder {
	m.blocks = append(m.blocks, MessageBlock{text: url, isURL: true})
	m.links = append(m.links, toolresult.Link{Label: label, URL: url})
	return m
}

// Build returns the message and its links, nil when it holds no URL.
func (m *MessageBuilder) Build() (string, []toolresult.Link) {
	parts := make([]string, 0, len(m.blocks))
	for _, b := range m.blocks {
		parts = append(parts, b.text)
	}
	return strings.Join(parts, "\n\n"), m.links
}

// PlainText makes text from the agent or the database safe inside a line of
// a personMessage: one line, no format or control character, full-width
// forms and lookalike slashes and dots folded, and nothing that reads as a
// URL, a bare host, a markdown link or a link fragment (a URL in a message
// is a link the engine hands over, on a line of its own).
func PlainText(s string) string {
	s = strings.Map(func(r rune) rune {
		if ascii, ok := lookalikes[r]; ok {
			return ascii
		}
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
	// Neutralize until stable: one change can join the pieces of another,
	// and a match consumes the label the next host dot needs.
	for prev := ""; prev != s; {
		prev = s
		s = linkLike.ReplaceAllString(s, " ")
		s = hostDot.ReplaceAllString(s, middleDot)
		s = dottedQuad.ReplaceAllString(s, quadDots)
		s = portPath.ReplaceAllString(s, spacedPort)
		s = letterPort.ReplaceAllString(s, spacedPort)
		s = markdownLink.ReplaceAllString(s, "] (")
	}
	return strings.Join(strings.Fields(s), " ")
}

// Clip shortens s to at most n characters, ending in "..." when it cuts.
func Clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-len(ellipsis)])) + ellipsis
}

// Shown is text from the agent or the database as it appears in a message.
func Shown(s string, n int) string { return Clip(PlainText(s), n) }

// fitMessage returns message, or, when it is over the 500-character limit,
// message with each of commands replaced by commandElsewhere. Every command
// a message offers also stands in a PERSON RUN_COMMAND step, in full.
func fitMessage(message string, commands ...string) string {
	if CheckPersonMessage(message) == nil {
		return message
	}
	for _, c := range commands {
		if c != "" {
			message = strings.ReplaceAll(message, c, commandElsewhere)
		}
	}
	return message
}

// FitToSteps is fitMessage with the commands of steps.
func FitToSteps(message string, steps []toolresult.NextStep) string {
	commands := make([]string, 0, len(steps))
	for _, st := range steps {
		commands = append(commands, st.Command)
	}
	return fitMessage(message, commands...)
}

// Full-width ASCII forms (U+FF01 to U+FF5E) fold to ASCII, so a full-width
// colon or slash cannot dodge the strip below.
const (
	fullWidthFirst rune = 0xff01
	fullWidthLast  rune = 0xff5e
	fullWidthShift rune = 0xfee0
)

// linkLike is what makes text look like a link or hold a link fragment: a
// scheme separator (slashes either way, as browsers read https:\\), "www.",
// and the fragment prefixes of the link formats.
var linkLike = regexp.MustCompile(`(?i)(:?[/\\]{2}|www\.|#1\.|#2\.|#s=|#h=)`)

// hostDot is a dot between two labels of a host name (evil.io,
// portal.basaltvault.app.evil.io). Chat apps link a bare host, so the dot
// becomes a middle dot: "evil·io" still reads, and links nowhere. A dot
// before a digit stays, so numbers like 1.5 keep theirs.
var hostDot = regexp.MustCompile(`([\p{L}\p{N}_-])\.(\p{L})`)

// middleDot replaces a host dot.
const middleDot = "$1·$2"

// dottedQuad is an IPv4 address (10.0.0.1); its dots become middle dots
// too, as do a version's with four parts. The short forms a browser also
// takes (0x7f.1, 127.1, decimal 2130706433) are left alone on purpose:
// chat apps do not link them, and without a scheme (removed above) they
// are not a URL.
var dottedQuad = regexp.MustCompile(`(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})`)

const quadDots = "$1·$2·$3·$4"

// hostPort is a port after a host (localhost:8080/x, http:8080): a space
// before the colon keeps it readable and unlinked. A port needs a path
// after it or a letter before it, so a time like 10:30 stays.
var (
	portPath   = regexp.MustCompile(`(\S):(\d{1,5}/)`)
	letterPort = regexp.MustCompile(`(\p{L}):(\d{1,5})\b`)
)

const spacedPort = "$1 :$2"

// markdownLink is the join of a markdown link, [text](target); a space
// breaks it and keeps both parts readable.
var markdownLink = regexp.MustCompile(`\]\(`)

// lookalikes are characters that read as, or that browsers and linkifiers
// map to, a slash, a backslash or a dot; they fold to the ASCII character so
// the patterns above catch them.
var lookalikes = map[rune]rune{
	'∕': '/',  // division slash
	'⁄': '/',  // fraction slash
	'╱': '/',  // box drawings light diagonal
	'⧸': '/',  // big solidus
	'⧵': '\\', // reverse solidus operator
	'⧹': '\\', // big reverse solidus
	'∖': '\\', // set minus
	'﹨': '\\', // small reverse solidus
	'․': '.',  // one dot leader
	'。': '.',  // ideographic full stop
	'﹒': '.',  // small full stop
	'｡': '.',  // halfwidth ideographic full stop
}

// ellipsis ends a clipped text.
const ellipsis = "..."

// commandElsewhere stands for a command a message would offer when the
// message with the command is over the limit (a long --config path). The
// full command is in the PERSON step the agent shows.
const commandElsewhere = "the command the agent shows you"
