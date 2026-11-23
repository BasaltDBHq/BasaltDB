package agent

import linksvc "github.com/basaltdbhq/basaltdb/internal/links"

// deliverRevert makes the notice of r, request_revert's answer: its link is
// that answer's revertUrl.
func (rc *revertCase) deliverRevert(kind linksvc.NoticeKind, r RequestedRevert) {
	rc.delivery.Deliver(linksvc.LinkNotice{
		Kind: kind, RevertID: r.Revert.ID, Headline: r.headline, ExpiresAt: r.Revert.ExpiresAt, Link: requestRevertFromDomain(r).RevertURL,
	})
}
