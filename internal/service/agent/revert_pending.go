package agent

import (
	"context"
	"fmt"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// PendingRevert is one open revert with what the agent hands the person:
// its headline, its link (none for a widened or APPLYING revert), the
// message and the next steps.
type PendingRevert struct {
	action.Revert
	Headline  string
	RevertURL string
	// RequestFile is the request beside a hash link in RevertURL.
	RequestFile   *links.RequestFile
	PersonMessage string
	Links         []toolresult.Link
	NextSteps     []toolresult.NextStep
	// issued is set when this list_pending issued the revert a new link.
	issued bool
}

// PendingRevert fills an open revert's headline, link, message and steps
// (CONTRACT.md, Reverts in list_pending): an APPLYING plan goes to the
// agent's batch loop; a PENDING revert goes to the person, at a new short
// link on reissue, at its long link otherwise, and on the page they
// widened on for a widened revert.
func (rc *revertCase) PendingRevert(ctx context.Context, p *PendingRevert, reissue bool) error {
	if p.Status == action.RevertApplying {
		headline, err := revertHeadline(p.Revert)
		if err != nil {
			return err
		}
		p.Headline = headline
		p.PersonMessage = fmt.Sprintf("%s You signed it; the agent restores it in batches by %s.", headline, applyByText(p.Revert))
		p.NextSteps = applyingSteps(p.ID)
		return nil
	}
	if reissue {
		r, err := rc.prepareReissue(ctx, p.Revert)
		if err != nil {
			return err
		}
		n, err := rc.revertNotice(ctx, r)
		if err != nil {
			return err
		}
		if n.tooLarge {
			return rc.pendingRevertTooLarge(p, r, n.URL, n.cost)
		}
		rc.notifyRevert(ctx, r, n)
		p.issued = n.short != ""
		p.Revert, p.Headline, p.RevertURL, p.RequestFile, p.PersonMessage, p.Links = r, n.Headline, n.URL, n.File, n.Message, n.Links
		p.NextSteps = guidance.WithSendRequest(pendingRevertSteps(r.ID, n.URL, "Open the new link, review the rows and sign with your passkey."), n.File)
		return nil
	}
	headline, err := revertHeadline(p.Revert)
	if err != nil {
		return err
	}
	p.Headline = headline
	expires := p.ExpiresAt.UTC().Format(guidance.PersonTime)
	if p.Widened {
		p.PersonMessage = fmt.Sprintf("%s %s It waits for your passkey on the page where you changed the scope, until %s.",
			widenedMessage, headline, expires)
		p.NextSteps = pendingRevertSteps(p.ID, "", "Sign with your passkey on the page where you changed the scope.")
		return nil
	}
	pick, err := rc.restatedRevertLink(ctx, p.Revert)
	if err != nil {
		return err
	}
	if pick.Kind == linksvc.LinkNone {
		return rc.pendingRevertTooLarge(p, p.Revert, pick.URL, linksvc.RevertRequestOf(p.Revert).Cost)
	}
	p.RevertURL, p.RequestFile = pick.URL, pick.File
	p.PersonMessage = fmt.Sprintf("%s It waits for your passkey at the link the agent gave you, until %s. If you lost it, "+
		"ask the agent for a new one.", headline, expires)
	open := p.RevertURL
	if rc.delivery.ShortLinked(p.ID) || pick.Kind == linksvc.LinkPage {
		open = "" // the person has the short link the agent handed over
	}
	p.NextSteps = guidance.WithSendRequest(pendingRevertSteps(p.ID, open,
		"Open the revert link the agent gave you, review the rows and sign with your passkey."), p.RequestFile)
	return nil
}

// pendingRevertTooLarge fills a pending revert whose request no link this
// engine has can carry (REQUEST_TOO_LARGE): the page's address, no
// request file, and the setup change as message and steps.
func (rc *revertCase) pendingRevertTooLarge(p *PendingRevert, r action.Revert, address string, cost int64) error {
	headline, err := revertHeadline(r)
	if err != nil {
		return err
	}
	steps, err := linksvc.RevertTooLargeSteps(r.ID, false)
	if err != nil {
		return err
	}
	p.Revert, p.Headline, p.RevertURL, p.RequestFile, p.Links = r, headline, address, nil, nil
	p.PersonMessage = rc.delivery.TooLargeMessage(guidance.Sentence(revertTitle(r)), cost, r.ExpiresAt, true)
	p.NextSteps = steps
	return nil
}

// pendingRevertSteps: the person signs (at link, or "" for the page they
// widened on), then the agent reads the result once.
func pendingRevertSteps(id uuid.UUID, link, open string) []toolresult.NextStep {
	return []toolresult.NextStep{
		guidance.OpenLink(link, open),
		guidance.CallTool(guidance.ToolRequestRevert, map[string]any{guidance.ArgRevertID: id.String(), guidance.ArgWaitForSignature: 0},
			"When the person says they signed, call this once; it returns at once."),
	}
}
