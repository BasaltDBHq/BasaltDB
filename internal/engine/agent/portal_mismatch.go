package agent

// portalVerifyCommand shows which files differ. It reads public pages only,
// needs no config and no engine, and is safe to run for anyone.
// addPortalProblem adds PORTAL_MISMATCH when the engine's last daily check
// found the portal serving pages other than the ones this build embeds
// (CONTRACT.md, CLI, basalt portal verify). A check that could not run, or
// no check yet, adds nothing.
func (s statusDeps) addPortalProblem(ps *problems) {
	if s.portal == nil {
		return
	}
	f, ok := s.portal.PortalFinding()
	if !ok || !f.Mismatch {
		return
	}
	when := f.CheckedAt.UTC().Format("2006-01-02")
	ps.add(problemPortalMismatch, "the portal serves pages that differ from this build ("+f.Summary+", checked "+when+")",
		func(b *Steps) string { return portalMismatchSteps(b, f.Summary, when) })
}

// portalMismatchSteps: the agent shows the person the finding. Whether to
// trust the portal is theirs to judge, even on an agent-operated engine.
func portalMismatchSteps(b *Steps, summary, when string) string {
	b.AskPerson("Show the person this message: they sign nothing on the portal until they know why, and can report it on GitHub.")
	return "The portal serves pages that differ from the ones in this basalt build (" + summary + ", checked " + when + "). " +
		"Do not sign anything on it until you know why, and report it on BasaltDB's GitHub issues."
}
