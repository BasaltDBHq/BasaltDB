package revert

import linksvc "github.com/basaltdbhq/basaltdb/internal/links"

// deliverRevert makes the notice of r, request_revert's answer: its link is
// that answer's revertUrl.
func (rc *Service) deliverRevert(kind linksvc.NoticeKind, r RequestedRevert) {
	rc.delivery.Deliver(linksvc.LinkNotice{
		Kind: kind, RevertID: r.Revert.ID, Headline: r.headline, ExpiresAt: r.Revert.ExpiresAt, Link: noticeLink(r),
	})
}

// noticeLink is the revert URL the notice carries: none for a widened revert,
// whose scope is the person's own.
func noticeLink(r RequestedRevert) string {
	if r.Revert.Widened {
		return ""
	}
	return r.RevertURL
}
