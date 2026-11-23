package agent

// deliverRevert makes the notice of r, request_revert's answer: its link is
// that answer's revertUrl.
func (rc *revertCase) deliverRevert(kind NoticeKind, r RequestedRevert) {
	rc.delivery.deliver(LinkNotice{
		Kind: kind, RevertID: r.Revert.ID, Headline: r.headline, ExpiresAt: r.Revert.ExpiresAt, Link: requestRevertFromDomain(r).RevertURL,
	})
}
