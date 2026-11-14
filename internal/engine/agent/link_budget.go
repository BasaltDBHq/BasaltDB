package agent

import (
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// The link budget (CONTRACT.md, Showing links). What the engine hands an
// agent as the way to open a page, in this order:
//
//  1. a short link, when one exists (the engine's local pages today; the
//     portal's short link over the Vault later, which only changes what the
//     caller passes as short);
//  2. else the long link, when it is at most the budget;
//  3. else the hash link, <page>#h=<h>, with the request beside it as a
//     file and text blocks (CONTRACT.md, The request file and pasted blocks).

// linkKind says which of the three the engine handed over.
type linkKind int

const (
	// linkShort is a short link: never measured.
	linkShort linkKind = iota + 1
	// linkLong is a long link within the budget.
	linkLong
	// linkHash is the hash link that stands in for a long link over the
	// budget; File carries the request.
	linkHash
	// linkPage is a page's address with no fragment, for a request too
	// large for a long link that a short link given earlier carries.
	linkPage
	// linkNone is the page's address of a request that no link this engine
	// has can carry (REQUEST_TOO_LARGE).
	linkNone
)

// handOver is the link the engine hands over, which of the three it is,
// and, for a hash link, the request to send beside it.
type handOver struct {
	URL  string
	Kind linkKind
	File *links.RequestFile
	// sent is set when the agent already sent File's request with an
	// earlier result: the message points back to it.
	sent bool
}

// chooseLink picks the link to hand over: short when it is not empty, else
// long, measured in characters of the whole URL (every link is ASCII) against
// budget, else the hash link with the request file named fileName.
func chooseLink(short, long string, budget int, fileName string) (handOver, error) {
	switch {
	case short != "":
		return handOver{URL: short, Kind: linkShort}, nil
	case len(long) <= budget:
		return handOver{URL: long, Kind: linkLong}, nil
	}
	hash, file, err := links.HashLink(long, fileName)
	if err != nil {
		return handOver{}, err
	}
	return handOver{URL: hash, Kind: linkHash, File: &file}, nil
}

// Labels of links next to a personMessage: what opening the link does
// (api/mcp/links/link.schema.json).
const (
	labelApprove = "Approve the held write"
	labelRevert  = "Review and sign the revert"
)

// requestBeside is how a message that hands over a hash link tells the
// person where the request comes from; withBlocks when the agent may paste
// it as text blocks too.
func requestBeside(withBlocks, sent bool) string {
	if sent {
		return "open this link, then open the request file the agent sent you earlier (or paste its text blocks). The page then shows a code for the agent:"
	}
	if withBlocks {
		return "open this link, then open the request file the agent sends you (or paste its text blocks). The page then shows a code for the agent:"
	}
	return "open this link, then open the request file the agent sends you. The page then shows a code for the agent:"
}

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

// plainText makes text from the agent or the database safe inside a line of
// a personMessage: one line, no format or control character, full-width
// forms and lookalike slashes and dots folded, and nothing that reads as a
// URL, a bare host, a markdown link or a link fragment (a URL in a message
// is a link the engine hands over, on a line of its own).
func plainText(s string) string {
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
// over: lead says what happened, tail lines follow the link.
func approvalMessage(lead string, pick handOver, command string, tail ...string) (string, []mcp.Link) {
	return fitCommand(
		func(c commandPhrases) (string, []mcp.Link) { return buildApprovalMessage(lead, pick, c, tail) },
		commandPhrases{orRun: "Or run: " + command},
		commandPhrases{orRun: "Or run the approve command the agent shows you."},
	)
}

// commandPhrases is the line of a message that offers the approve command,
// after the link.
type commandPhrases struct{ orRun string }

// fitCommand builds a message with the full command and, when that breaks
// the 500-character limit (a long --config path), again with a line that
// sends the person to the command in the step the agent shows. The full
// command stays in approval.approveCommand and in the step.
func fitCommand(build func(commandPhrases) (string, []mcp.Link), full, short commandPhrases) (string, []mcp.Link) {
	text, ls := build(full)
	if CheckPersonMessage(text) == nil {
		return text, ls
	}
	return build(short)
}

// commandElsewhere stands for a command a message would offer when the
// message with the command is over the limit (a long --config path). The
// full command is in the PERSON step the agent shows.
const commandElsewhere = "the command the agent shows you"

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

// fitToSteps is fitMessage with the commands of steps.
func fitToSteps(message string, steps []NextStep) string {
	commands := make([]string, 0, len(steps))
	for _, st := range steps {
		commands = append(commands, st.Command)
	}
	return fitMessage(message, commands...)
}

func buildApprovalMessage(lead string, pick handOver, c commandPhrases, tail []string) (string, []mcp.Link) {
	msg := newMessage().Text(lead)
	switch pick.Kind {
	case linkHash:
		msg.Text("Approve it with your passkey: " + requestBeside(pick.File.Blocks != nil, pick.sent))
	case linkLong:
		msg.Text("Approve it with your passkey here; the page then shows a code for the agent:")
	default:
		msg.Text("Approve it with your passkey here:")
	}
	msg.Link(labelApprove, pick.URL).Text(c.orRun)
	for _, line := range tail {
		msg.Text(line)
	}
	return msg.Build()
}

// revertMessage is the personMessage of a prepared revert at the link handed
// over: what it restores, why, and when it expires, then the link.
func revertMessage(summary string, pick handOver, extra ...string) (string, []mcp.Link) {
	msg := newMessage().Text(summary)
	for _, line := range extra {
		msg.Text(line)
	}
	sign := "Sign it with your passkey here:"
	switch pick.Kind {
	case linkShort, linkPage, linkNone:
	case linkHash:
		sign = "Sign it with your passkey: " + requestBeside(pick.File.Blocks != nil, pick.sent)
	case linkLong:
		sign = "Sign it with your passkey here; the page then shows a code for the agent:"
	}
	return msg.Text(sign).Link(labelRevert, pick.URL).Build()
}

// expiryLine states a deadline for a person.
func expiryLine(t time.Time) string { return "Expires " + t.UTC().Format(personTime) + "." }
