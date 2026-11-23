package agent

import "github.com/basaltdbhq/basaltdb/internal/core/guidance"

// portalVerifyCommand shows which files differ. It reads public pages only,
// needs no config and no engine, and is safe to run for anyone.
// addPortalProblem adds PORTAL_MISMATCH when the engine's last daily check
// found the portal serving pages other than the ones this build embeds
// (CONTRACT.md, CLI, basalt portal verify). A check that could not run, or
// no check yet, adds nothing.
func (s statusDeps) addPortalProblem(ps *guidance.Problems) {
	if s.portal == nil {
		return
	}
	f, ok := s.portal.PortalFinding()
	if !ok || !f.Mismatch {
		return
	}
	when := f.CheckedAt.UTC().Format("2006-01-02")
	ps.Add(problemPortalMismatch, "the portal serves pages that differ from this build ("+f.Summary+", checked "+when+")",
		func(b *guidance.Steps) string { return portalMismatchSteps(b, f.Summary, when) })
}

// portalMismatchSteps: the person looks at which files differ. The step is
// the person's even on an agent-operated engine: whether to trust the portal
// is theirs to judge.
func portalMismatchSteps(b *guidance.Steps, summary, when string) string {
	b.AskPerson("Tell the person the portal serves pages that differ from this build, and that they sign nothing there until they know why.")
	return "The portal serves pages that differ from the ones in this basalt build (" + summary + ", checked " + when + "). " +
		"Do not sign anything on it until you know why."
}
