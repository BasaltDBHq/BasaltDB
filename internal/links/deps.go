package links

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	corelinks "github.com/basaltdbhq/basaltdb/internal/core/links"
)

// Core is what the delivery use case reads of the agent's shared settings: who
// the agent is, the log and clock, the commands the person runs, how errors map
// to the contract, and where the pages are. It is a copy taken when the service
// is built.
type Core struct {
	Name string
	Log  *slog.Logger
	Now  func() time.Time
	// Commands builds the commands the person runs for this agent.
	Commands guidance.Commands
	// Errors tells apart the error values of the adapters.
	Errors guidance.ErrorMap
	// PagesBase is the base URL of the approval and revert pages (links).
	PagesBase string
	// PagesOrigin is the origin of the pages the engine serves itself, for
	// short links; empty when it serves none.
	PagesOrigin string
}

// Deps is how a held write or a revert reaches the person: the
// notices, the short links and the receipts of what the person signed.
type Deps struct {
	// Notifier is optional: no notification when nil.
	Notifier Notifier
	// Deliverer takes the notice of each answer that holds a write, prepares
	// a revert or issues a new link on the agent's request, for the
	// approval.deliver plugins; optional, none when nil.
	Deliverer LinkDeliverer
	// Links holds the short links' secrets, shared with the pages; a store
	// of its own when nil.
	Links *corelinks.Secrets
	// Relay registers portal short links with the Vault; optional, none
	// when nil (the Vault is off).
	Relay LinkRelay
	// VaultConflict reports whether err is the Vault's answer that another
	// engine holds a link's token. ErrVaultNotConnected is what a relay
	// answers when no Vault is connected.
	VaultConflict        func(err error) bool
	ErrVaultNotConnected error
	// Poll is how often a waiting call reads whether the person signed;
	// DefaultPoll when zero.
	Poll time.Duration
	// Receipts is the engine's signing key, which signs the receipt of
	// every signature the engine relays (CONTRACT.md, Vault channel,
	// Receipts). Nil when the key file is refused (KEY_ERROR): answers then
	// carry noReceipt.
	Receipts ReceiptSigner
}
