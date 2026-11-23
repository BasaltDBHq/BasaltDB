package agent

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
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
		return "open this link, then open the request file the agent sent you earlier (or paste its text blocks):"
	}
	if withBlocks {
		return "open this link, then open the request file the agent sends you (or paste its text blocks):"
	}
	return "open this link, then open the request file the agent sends you:"
}

// reviewOnly is how a message that hands over a long or hash link says the
// page cannot be signed: only a short link (the engine's own pages, or the
// portal through Basalt Vault) carries a signature back to the engine. An
// engine whose Vault connection is down hands one over too; once it is back,
// a new link from the agent (reissueLink) is a short link.
const (
	reviewOnly       = "Review only: this link cannot be signed. Ask the agent for a new link later."
	reviewOnlyBeside = "Review only, this link cannot be signed: "
)

// Limits that keep what the agent supplies, and what the database names,
// from pushing a message over its 500 characters.
const (
	maxHeadlineChars = 100
	maxIntentChars   = 80
)

// approvalMessage is the personMessage of a held write at the link handed
// over: lead says what happened, tail lines follow the link.
func approvalMessage(lead string, pick handOver, tail ...string) (string, []toolresult.Link) {
	return buildApprovalMessage(lead, pick, tail)
}

func buildApprovalMessage(lead string, pick handOver, tail []string) (string, []toolresult.Link) {
	msg := guidance.NewMessage().Text(lead)
	switch pick.Kind {
	case linkHash:
		msg.Text(reviewOnlyBeside + requestBeside(pick.File.Blocks != nil, pick.sent))
	case linkLong:
		msg.Text(reviewOnly)
	default:
		msg.Text("Approve it with your passkey here:")
	}
	msg.Link(labelApprove, pick.URL)
	for _, line := range tail {
		msg.Text(line)
	}
	return msg.Build()
}

// revertMessage is the personMessage of a prepared revert at the link handed
// over: what it restores, why, and when it expires, then the link.
func revertMessage(summary string, pick handOver, extra ...string) (string, []toolresult.Link) {
	msg := guidance.NewMessage().Text(summary)
	for _, line := range extra {
		msg.Text(line)
	}
	sign := "Sign it with your passkey here:"
	switch pick.Kind {
	case linkShort, linkPage, linkNone:
	case linkHash:
		sign = reviewOnlyBeside + requestBeside(pick.File.Blocks != nil, pick.sent)
	case linkLong:
		sign = reviewOnly
	}
	return msg.Text(sign).Link(labelRevert, pick.URL).Build()
}

// expiryLine states a deadline for a person.
func expiryLine(t time.Time) string { return "Expires " + t.UTC().Format(personTime) + "." }
