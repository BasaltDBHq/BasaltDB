package status

// PortalFinding is the last check's result for status: the daily portal
// check (CONTRACT.md, CLI, basalt portal verify) as the agents' status reads
// it.
func (c *Checker) PortalFinding() (PortalFinding, bool) {
	r, ok := c.Last()
	if !ok {
		return PortalFinding{}, false
	}
	return PortalFinding{CheckedAt: r.CheckedAt, Mismatch: r.Mismatch(), Summary: r.Summary()}, true
}
