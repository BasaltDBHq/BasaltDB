package vault

import (
	"context"
	"errors"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// Link registration (CONTRACT.md, Vault channel, The engine's socket to the
// Vault). Before handing over a portal short link the engine registers its
// linkToken and waits up to RegisterTimeout for OK; with no socket, an ERROR
// or no answer the caller hands over the long link instead. Only the token
// and the link's expiry are ever sent: never the link secret or its psk.

// RegisterTimeout is how long the engine waits for the Vault to answer a
// REGISTER_LINK before it hands over the long link.
const RegisterTimeout = 5 * time.Second

// ErrNotConnected is a registration with no READY socket to send it on, or
// whose socket ended before the answer came.
var ErrNotConnected = errors.New("vault: not connected")

// ErrNoAnswer is a registration the Vault did not answer within RegisterTimeout.
var ErrNoAnswer = errors.New("vault: no answer to the link registration")

// RefusedError is a registration the Vault answered with ERROR.
type RefusedError struct{ Code string }

func (e *RefusedError) Error() string { return "vault: the Vault refused the link: " + e.Code }

// IsConflict reports whether err is the Vault's LINK_CONFLICT: another
// engine registered the token (VC-42).
func IsConflict(err error) bool {
	var r *RefusedError
	return errors.As(err, &r) && r.Code == CodeLinkConflict
}

// Link is a live link the engine registers again after every READY.
type Link struct {
	Token     channel.LinkToken
	ExpiresAt time.Time
}

// Links are the engine's live relay links, across its agents.
type Links interface {
	// Live lists every live relay link.
	Live() []Link
	// Conflict revokes the link of token: another engine registered it
	// (VC-42), so its next link gets a new secret whose token nobody else
	// knows. It runs on the socket's read loop, so it must not block or
	// write to the socket: it does not unregister the token, which the Vault
	// already said is not this engine's.
	Conflict(token channel.LinkToken)
}

// noLiveLinks is Links for an engine with none.
type noLiveLinks struct{}

func (noLiveLinks) Live() []Link                 { return nil }
func (noLiveLinks) Conflict(_ channel.LinkToken) {}

// answer is the Vault's OK (code empty) or ERROR to one request.
type answer struct{ code string }

// Connected reports whether the socket is READY now.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur != nil
}

// current is the READY socket, or nil.
func (c *Client) current() *conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

// Register asks the Vault to route page sockets for token to this engine
// until expiresAt, and waits for its answer: nil for OK, ErrNotConnected,
// ErrNoAnswer after RegisterTimeout, a *RefusedError for ERROR, or ctx's
// error. Anything but nil means the link must not be handed over.
func (c *Client) Register(ctx context.Context, token channel.LinkToken, expiresAt time.Time) error {
	cn := c.current()
	if cn == nil {
		return ErrNotConnected
	}
	rctx, cancel := context.WithTimeout(ctx, c.opts.RegisterTimeout)
	defer cancel()
	got := make(chan answer, 1)
	ref, err := cn.send(rctx, func(ref int64) any { return registerMsg(ref, token, expiresAt) },
		func(a answer) { got <- a })
	if err != nil {
		if ctx.Err() == nil && rctx.Err() != nil {
			return ErrNoAnswer
		}
		return err
	}
	select {
	case a := <-got:
		if a.code != "" {
			return &RefusedError{Code: a.code}
		}
		return nil
	case <-cn.done:
		return ErrNotConnected
	case <-rctx.Done():
		cn.forget(ref)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrNoAnswer
	}
}

// Unregister tells the Vault to stop routing token, without waiting for the
// answer (CONTRACT.md: a reissue does not wait, and a LINK_CONFLICT there
// stops nothing). With no socket it does nothing: the Vault drops the token
// at its expiry, and the engine refuses its sessions either way.
func (c *Client) Unregister(token channel.LinkToken) {
	cn := c.current()
	if cn == nil {
		return
	}
	log := c.opts.Log
	err := cn.sendNoWait(context.Background(), func(ref int64) any {
		return unregisterLinkMsg{Type: typeUnregisterLink, Ref: ref, LinkToken: token.String()}
	}, func(a answer) {
		if a.code != "" {
			log.Warn("vault: unregistering a link was refused", "linkToken", token.String(), "code", a.code)
		}
	})
	if err != nil {
		log.Warn("vault: could not unregister a link; the Vault drops it at its expiry", "linkToken", token.String(), "err", err)
	}
}

// registerMsg is REGISTER_LINK for token until expiresAt. expiresAt goes in
// whole seconds, rounded down, so the Vault drops the token at most a second
// before the engine drops the link, never after.
func registerMsg(ref int64, token channel.LinkToken, expiresAt time.Time) registerLinkMsg {
	return registerLinkMsg{
		Type: typeRegisterLink, Ref: ref, LinkToken: token.String(),
		ExpiresAt: expiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
}

// sendNoWait is send for a request nobody waits on: its answer, if one
// comes within RegisterTimeout, goes to onAnswer; after that the ref is
// forgotten, so a silent Vault cannot make pending grow without bound.
func (cn *conn) sendNoWait(ctx context.Context, build func(ref int64) any, onAnswer func(answer)) error {
	ref, err := cn.send(ctx, build, onAnswer)
	if err != nil {
		return err
	}
	time.AfterFunc(cn.c.opts.RegisterTimeout, func() { cn.forget(ref) })
	return nil
}

// pendingLen is how many requests wait for an answer.
func (cn *conn) pendingLen() int {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return len(cn.pending)
}

// send writes the request build makes with a fresh ref and keeps onAnswer
// for the Vault's answer to that ref. It returns the ref.
func (cn *conn) send(ctx context.Context, build func(ref int64) any, onAnswer func(answer)) (int64, error) {
	cn.mu.Lock()
	cn.nextRef++
	ref := cn.nextRef
	cn.pending[ref] = onAnswer
	cn.mu.Unlock()
	if err := writeJSON(ctx, cn.ws, build(ref)); err != nil {
		cn.forget(ref)
		return 0, err
	}
	return ref, nil
}

// forget stops waiting for ref's answer; a late one is then ignored.
func (cn *conn) forget(ref int64) {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	delete(cn.pending, ref)
}

// answered hands an OK or ERROR to the request of its ref. An answer to no
// request waiting (a forged or late one) is ignored: it cannot make the
// engine hand over a link it did not register.
func (cn *conn) answered(ref *int64, a answer) {
	if ref == nil {
		cn.c.opts.Log.Warn("vault socket: an ERROR to no request", "code", a.code)
		return
	}
	cn.mu.Lock()
	onAnswer, ok := cn.pending[*ref]
	delete(cn.pending, *ref)
	cn.mu.Unlock()
	if !ok {
		cn.c.opts.Log.Debug("vault socket: an answer to no request", "ref", *ref)
		return
	}
	onAnswer(a)
}

// registerAll registers every live link again after READY (CONTRACT.md: so
// a Vault that lost its state recovers), without waiting for the answers. A
// LINK_CONFLICT revokes that link (VC-42).
func (cn *conn) registerAll(ctx context.Context) {
	links := cn.c.opts.Links
	log := cn.c.opts.Log
	for _, l := range links.Live() {
		token := l.Token
		err := cn.sendNoWait(ctx, func(ref int64) any { return registerMsg(ref, token, l.ExpiresAt) }, func(a answer) {
			switch a.code {
			case "":
			case CodeLinkConflict:
				log.Warn("vault: another engine registered this link's token; the link is revoked, "+
					"and the item's next link (list_pending with reissueLink) gets a new one", "linkToken", token.String())
				links.Conflict(token)
			default:
				log.Warn("vault: the Vault refused a link registered again", "linkToken", token.String(), "code", a.code)
			}
		})
		if err != nil {
			log.Warn("vault: registering the links again stopped", "err", err)
			return
		}
	}
}
