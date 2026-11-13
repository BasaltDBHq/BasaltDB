package telegram

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
)

// Telegram limits.
const (
	// maxTextUnits is the Bot API's sendMessage text limit: 4096 characters
	// after entity parsing, counted in UTF-16 code units.
	maxTextUnits = 4096
	// maxButtonURLBytes is the longest link sent as an inline button. The
	// Bot API does not document a button URL limit; this is a conservative
	// guess, confirmed or raised by the owner's live test (roadmap, Held for
	// owner). Longer links go in the message text.
	maxButtonURLBytes = 2048
	// maxStatementRunes and maxIntentRunes keep the summary short; the full
	// statement is on the approval page.
	maxStatementRunes = 400
	maxIntentRunes    = 300
	// maxHeadlineRunes keeps a held write's headline (approval.Summary) to
	// a few lines; the counts and the largest cascades come first.
	maxHeadlineRunes = 1000
)

// ButtonText labels the approval link.
const ButtonText = "Review and approve"

// Notice is a held write waiting for the person's passkey.
type Notice struct {
	ApprovalID uuid.UUID
	Agent      string
	Database   string
	Intent     string
	Statement  string
	// Headline is approval.Summary.Headline: what the write changes, with
	// its cascaded rows stated (owner decision, Nov 12).
	Headline    string
	ExpiresAt   time.Time
	ApprovalURL string
	// ShortURL is the engine's short link with its secret, when it serves
	// the pages; it opens on the engine's machine only.
	ShortURL string
}

// Notifier tells the person on Telegram that a write is held.
type Notifier struct {
	client *Client
}

// NewNotifier panics on a nil client: it is required.
func NewNotifier(client *Client) *Notifier {
	if client == nil {
		panic("telegram.NewNotifier: nil client")
	}
	return &Notifier{client: client}
}

// NotifyHeld sends the held write's summary and its approval link.
func (n *Notifier) NotifyHeld(ctx context.Context, h Notice) error {
	return n.client.SendMessage(ctx, HeldMessage(h))
}

// HeldMessage builds the message for a held write. The link goes in a button
// when it is short enough, else in the text when the text stays under
// Telegram's limit, else the person is told to open it from their computer
// with basalt approve --show.
func HeldMessage(h Notice) Message {
	summary := fmt.Sprintf("BasaltDB: approval needed\n\n%s\n\nAgent: %s on %s\nWhy: %s\nStatement: %s\nExpires: %s",
		truncate(h.Headline, maxHeadlineRunes),
		h.Agent, h.Database,
		truncate(h.Intent, maxIntentRunes),
		truncate(h.Statement, maxStatementRunes),
		h.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	if h.ShortURL != "" {
		summary += "\nOn the engine's computer: " + h.ShortURL
	}
	if len(h.ApprovalURL) <= maxButtonURLBytes {
		return Message{Text: summary, Button: &Button{Text: ButtonText, URL: h.ApprovalURL}}
	}
	withLink := summary + "\n\nReview and approve: " + h.ApprovalURL
	if utf16Len(withLink) <= maxTextUnits {
		return Message{Text: withLink}
	}
	return Message{Text: summary + "\n\nThe preview is too large for a Telegram link. On your computer, run:\nbasalt approve --show " + h.ApprovalID.String()}
}

// RevertButtonText labels the revert link.
const RevertButtonText = "Review and sign"

// RevertNotice is a revert waiting for the person's signature: prepared by
// the agent, or its link issued again (owner decision LP-2).
type RevertNotice struct {
	RevertID uuid.UUID
	Agent    string
	Database string
	// Headline is built from what Postgres returned for the revert.
	Headline  string
	Intent    string
	ExpiresAt time.Time
	// RevertURL is the long link; ShortURL the engine's short link with
	// its secret, when it serves the pages.
	RevertURL string
	ShortURL  string
	// Widened is a revert the person widened: the notice carries only the
	// headline (LP-3).
	Widened bool
}

// NotifyRevert sends a revert's summary and its link.
func (n *Notifier) NotifyRevert(ctx context.Context, r RevertNotice) error {
	return n.client.SendMessage(ctx, RevertMessage(r))
}

// RevertMessage builds the message for a revert, as HeldMessage does for a
// held write: the link in a button when it is short enough, else in the
// text, else the person is told to open it from their computer. A widened
// revert's message is its headline only (LP-3).
func RevertMessage(r RevertNotice) Message {
	headline := truncate(r.Headline, maxHeadlineRunes)
	if r.Widened {
		return Message{Text: "BasaltDB: revert waiting for your signature\n\n" + headline}
	}
	summary := fmt.Sprintf("BasaltDB: revert waiting for your signature\n\n%s\n\nAgent: %s on %s\nWhy: %s\nExpires: %s",
		headline, r.Agent, r.Database, truncate(r.Intent, maxIntentRunes), r.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	if r.ShortURL != "" {
		summary += "\nOn the engine's computer: " + r.ShortURL
	}
	if r.RevertURL != "" && len(r.RevertURL) <= maxButtonURLBytes {
		return Message{Text: summary, Button: &Button{Text: RevertButtonText, URL: r.RevertURL}}
	}
	withLink := summary + "\n\nReview and sign: " + r.RevertURL
	if r.RevertURL != "" && utf16Len(withLink) <= maxTextUnits {
		return Message{Text: withLink}
	}
	return Message{Text: summary + "\n\nThe revert link is too long for Telegram: ask the agent for it."}
}

// truncate shortens s to at most n runes, marking the cut.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func utf16Len(s string) int {
	return len(utf16.Encode([]rune(s)))
}
