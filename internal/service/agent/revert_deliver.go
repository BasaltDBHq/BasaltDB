package agent

// deliverRevert makes the notice of r, request_revert's answer: its link is
// that answer's revertUrl.
func (s *Service) deliverRevert(kind NoticeKind, r RequestedRevert) {
	s.deliver(LinkNotice{
		Kind: kind, RevertID: r.Revert.ID, Headline: r.headline, ExpiresAt: r.Revert.ExpiresAt, Link: requestRevertFromDomain(r).RevertURL,
	})
}
