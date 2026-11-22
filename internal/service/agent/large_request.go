package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// Requests too large for a link (CONTRACT.md, Large values). A held write's
// or revert's long link, hash link and request file carry its binding text
// and lines whole, and a page decodes at most 1 MiB of them (Format 2,
// Limits). A larger request reaches a page only on a short link whose page
// fetches it from the engine: the engine's local pages, or the portal over
// the Vault when its lines cost at most maxPortalRequestCost. With neither,
// the answer is REQUEST_TOO_LARGE.

// argReissueLink is list_pending's and request_revert's argument that
// issues a new link.
const argReissueLink = "reissueLink"

// reasonRequestTooLarge is APPROVAL_REQUIRED's and QUERY_TIMEOUT's reason,
// and the results case, for a request no link this engine has can carry.
const reasonRequestTooLarge = "REQUEST_TOO_LARGE"

// maxPortalRequestCost is the most a request's lines may cost, in the
// budget's unit, on the portal's short link: the page's response over the
// Vault is at most 16 MiB, and the rest of it fits in the remaining 1 MiB.
const maxPortalRequestCost = 15 << 20

// textOverhead is what one text costs beyond its bytes (resultsize's
// per-value cost).
const textOverhead = 128

// textsCost is what texts cost in the budget's unit (ledger.textCost): each
// one's bytes, 6 more for each byte JSON escapes, and 128.
func textsCost(texts []string) int64 {
	var n int64
	for _, t := range texts {
		n += int64(len(t)) + textOverhead
		for i := range len(t) {
			if c := t[i]; c < ' ' || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
				n += 6
			}
		}
	}
	return n
}

// sizedRequest is the request of a held write or revert as the engine has
// it: the binding text, and the lines unless an agent's read left them out
// (LeftOut: Lines are then their heads), with what the lines cost.
type sizedRequest struct {
	Binding string
	Lines   []string
	LeftOut bool
	Cost    int64
}

// longOrTooLarge builds the request's long link with build, or reports the
// request too large for one: its lines were left out, or the page would
// refuse to decode it (linkcodec.ErrRequestTooLarge).
func longOrTooLarge(r sizedRequest, build func() (string, error)) (string, bool, error) {
	if r.LeftOut {
		return "", true, nil
	}
	long, err := build()
	if errors.Is(err, linkcodec.ErrRequestTooLarge) {
		return "", true, nil
	}
	return long, false, err
}

// largeShortLink issues a new short link that can carry a request too large
// for any other link (revoking the item's earlier one): the portal's when
// the Vault registers it and the lines cost at most maxPortalRequestCost,
// else one to the local pages; "" when there is none.
func (s *Service) largeShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, cost int64) (string, error) {
	if cost <= maxPortalRequestCost {
		if link := s.relayLink(ctx, page, id, expires); link != "" {
			return link, nil
		}
	}
	return s.localLink(page, id, expires)
}

// carriesLarge reports whether a short link this engine hands over can
// carry a request whose lines cost cost: the local pages always, the
// portal's over a READY Vault up to maxPortalRequestCost.
func (s *Service) carriesLarge(cost int64) bool {
	return s.PagesOrigin != "" || (cost <= maxPortalRequestCost && s.Relay.Connected())
}

// pageAddress is an item's page with no fragment: what a field that would
// restate a long link carries for a request too large for one.
func (s *Service) pageAddress(page func(string, uuid.UUID) string, id uuid.UUID) string {
	if s.PagesOrigin != "" {
		return page(s.PagesOrigin, id)
	}
	return page(s.PagesBase, id)
}

// revertRequestOf is r's request as the agent's read returned it.
func revertRequestOf(r ledger.Revert) sizedRequest {
	return sizedRequest{Binding: r.BindingText, Lines: r.Lines, LeftOut: r.LinesLeftOut, Cost: max(r.LinesCost, textsCost(r.Lines))}
}

// isPageAddress reports whether url is a page's address with no fragment
// (pageAddress): a short link handed over earlier carries the request, and
// the person opens that one. Every link the engine hands over has one.
func isPageAddress(url string) bool {
	return url != "" && !strings.Contains(url, "#")
}

// tooLargeMessage is the REQUEST_TOO_LARGE personMessage for what (the held
// write, or a revert), whose lines cost cost and which expires at expires,
// by the engine's setup (CONTRACT.md, Large values, rule 5).
func (s *Service) tooLargeMessage(what string, cost int64, expires time.Time, isRevert bool) string {
	return s.tooLargeText(what, cost, expires, isRevert)
}

// tooLargeText is tooLargeMessage's text. A setup change goes through the
// agent's basalt init, whose link opens the page for it.
func (s *Service) tooLargeText(what string, cost int64, expires time.Time, isRevert bool) string {
	lead := what + " is too large for a link, so no link was given."
	until := " It expires at " + expires.UTC().Format(personTime) + "."
	narrower := ""
	if isRevert {
		narrower = " Or ask the agent for a narrower revert (only some runs or tables)."
	}
	switch {
	case s.PagesBase != links.Portal:
		return lead + " To open it, turn on the engine's local pages (pagesAddr in engine.json), restart the engine, then tell the agent." +
			narrower + until
	case cost <= maxPortalRequestCost:
		// Only the Vault carries a too-large request's portal short link.
		return lead + " To open it, turn on the Vault: ask the agent, it gives you a link for that. Then tell the agent." + narrower + until
	case s.Commands.AgentOperated():
		return what + " is too large for any page this engine can serve: only local pages can carry it, and an agent-operated " +
			"engine has none. It cannot be opened on this setup unless the setup changes; otherwise it expires." + narrower + until
	}
	return lead + " Only local pages can carry it: set a local pagesUrl and pagesAddr in engine.json, restart the engine, " +
		"register a passkey for that origin (the agent gives you a link), then tell the agent." + narrower + until
}

// tooLargeAsk is the ASK_PERSON text of REQUEST_TOO_LARGE.
func tooLargeAsk(isRevert bool) string {
	if isRevert {
		return "Show personMessage: no link can carry this revert. Ask them to change the setup and tell you before opening it, " +
			"or for a narrower one: request_revert with runs or tables."
	}
	return "Show personMessage: no link this engine has can carry this held write. Ask the person to change the setup " +
		"as it says and to tell you when it is done."
}

// endTurnSetup is the END_TURN text of REQUEST_TOO_LARGE.
const endTurnSetup = "End your turn: the person changes the setup first."

// approvalTooLargeSteps are the steps of a held write too large for a link:
// the person changes the setup, then the agent asks for new links for the
// run's pending holds.
func approvalTooLargeSteps(runID uuid.UUID) ([]mcp.NextStep, error) {
	return NewSteps().AskPerson(tooLargeAsk(false)).EndTurn(endTurnSetup).
		CallTool(toolListPending, map[string]any{"kind": KindApproval, "status": "PENDING", argRunID: runID.String(), argReissueLink: true},
			"Once the person says they changed the setup, call this once: it gives the held write a new link.").
		Build()
}

// revertTooLargeSteps are the steps of a revert too large for a link: on
// request_revert's error a STOP first (stop), then the person changes the
// setup or asks for a narrower revert, and the agent asks for a new link
// for this revert only.
func revertTooLargeSteps(id uuid.UUID, stop bool) ([]mcp.NextStep, error) {
	b := NewSteps()
	if stop {
		b.Stop("Do not retry now: no link this engine has can carry this revert.")
	}
	return b.AskPerson(tooLargeAsk(true)).EndTurn(endTurnSetup).
		CallTool(toolRequestRevert, map[string]any{argRevertID: id.String(), argReissueLink: true},
			"Once the person says they changed the setup, call this once: it gives this revert a new link.").
		Build()
}

// revertTooLargeError is request_revert's QUERY_TIMEOUT REQUEST_TOO_LARGE:
// the revert is prepared and waits until it expires, but no link this
// engine has can carry it.
func (s *Service) revertTooLargeError(id uuid.UUID, cost int64, expires time.Time) error {
	steps, err := revertTooLargeSteps(id, true)
	if err != nil {
		return err
	}
	return &mcp.ToolError{
		Code: CodeQueryTimeout, Reason: reasonRequestTooLarge,
		Message: fmt.Sprintf("revert %s is prepared, but its rows are too large for any link this engine has: "+
			"a page decodes at most 1 MiB from a link. It stays pending until it expires (list_pending lists it); "+
			"do what nextSteps say.", id),
		PersonMessage: s.tooLargeMessage(fmt.Sprintf("The revert %s", id), cost, expires, true),
		NextSteps:     steps,
	}
}
