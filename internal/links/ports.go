package links

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// LinkDeliverer takes the notice of an answer the agent is about to get, or
// of a write just held whose call waits for the person. DeliverLink must
// return at once: it runs on the agent's call, after the answer that holds
// the link is built, and nothing it does may delay or change the call's
// answer. It returns nothing, so the answer cannot depend on it.
type LinkDeliverer interface {
	DeliverLink(n LinkNotice)
}

// Notifier tells the person a write is held or a revert waits for them.
// The engine has no notifier today, so it is NoNotifier; it is the seam a
// notification channel plugs into later. It only delivers the link;
// approving and signing need the person's passkey.
type Notifier interface {
	NotifyHeld(ctx context.Context, n HeldNotice) error
	NotifyRevert(ctx context.Context, n RevertNotice) error
}

// ColumnOrder reads resources' fields in the order their store keeps them.
type ColumnOrder interface {
	// ColumnOrder maps each resource name, as the lines spell it, to its
	// field names in the store's order; a resource it cannot find is left
	// out.
	ColumnOrder(ctx context.Context, resources []string) (map[string][]string, error)
}

// ReceiptSigner is the engine's signing key (*channel.EngineKeys), which
// signs the receipt of every signature the engine relays (CONTRACT.md,
// Vault channel, Receipts).
type ReceiptSigner interface {
	channel.Signer
	EngineID() string
	Fingerprint() string
}

// LinkRelay registers portal short links with the Vault (CONTRACT.md, Vault
// channel, The engine's socket to the Vault). *vault.Client is the one
// implementation outside tests.
type LinkRelay interface {
	// Connected reports whether the engine's socket is READY.
	Connected() bool
	// Register routes token to this engine until expiresAt; any error
	// means the link must not be handed over.
	Register(ctx context.Context, token channel.LinkToken, expiresAt time.Time) error
}

// ApprovalReads is the part of the approval group that delivery reads.
type ApprovalReads interface {
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
	FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error)
	// HasColumns says whether the pages can show the resources' field order.
	HasColumns() bool
	ColumnOrder(ctx context.Context, resources []string) (map[string][]string, error)
}
