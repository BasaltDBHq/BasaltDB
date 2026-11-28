package agent

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// DescribeOverview counts what the agent can see, lists it (up to 50
// resources) or its namespaces, and tells the person how to see what it
// cannot.
func (ds *Service) DescribeOverview(ctx context.Context) (Overview, error) {
	visible, ungranted, err := ds.store.Catalog.Resources(ctx)
	if err != nil {
		return Overview{}, err
	}
	lines, err := ds.store.Catalog.Structure(ctx)
	if err != nil {
		return Overview{}, err
	}
	notGranted := ungranted.Total()
	pii, err := ds.store.Classes.CatalogFingerprint(ctx)
	if err != nil {
		return Overview{}, err
	}
	limits := ds.store.Data.Limits()
	o := Overview{
		Store:       StoreInfo{Kind: string(ds.store.Kind), Database: ds.store.Catalog.Database(), Host: ds.store.Catalog.Host()},
		Fingerprint: catalogFingerprint(lines, notGranted, pii),
		Counts:      Counts{Resources: len(visible), NotGranted: notGranted},
		Update:      ds.update(),
		Limits: OverviewLimits{
			ReadRowLimit: limits.ReadRowLimit, StatementTimeoutMs: limits.StatementTimeout.Milliseconds(), WritePolicy: writePolicy,
		},
	}
	namespaces := namespaceCounts(visible)
	o.Counts.Namespaces = len(namespaces)
	split := splitNotGranted(namespaces, ungranted)
	o.Counts.NotGrantedInGrantedNamespaces = split.inGranted
	o.Counts.NotGrantedInOtherNamespaces = split.other
	o.Counts.NotGrantedNamespaces = split.otherNamespaces
	b := guidance.NewSteps()
	switch {
	case len(visible) > overviewInlineMax:
		o.Namespaces, o.OtherNamespaces = capNamespaces(namespaces)
		overviewLargeSteps(b, o.Namespaces)
	default:
		o.Resources = make([]SearchItem, 0, len(visible))
		for _, r := range visible {
			o.Resources = append(o.Resources, ds.searchItem(r, ""))
		}
	}
	if notGranted > 0 {
		o.PersonMessage = ds.notGrantedSteps(b, split)
	}
	if o.Namespaces == nil && notGranted == 0 {
		return o, nil
	}
	if o.NextSteps, err = b.Build(); err != nil {
		return Overview{}, err
	}
	return o, nil
}

// namespaceCounts counts the visible resources of each namespace, by
// namespace name.
func namespaceCounts(visible []agentstore.Resource) []NamespaceCount {
	var out []NamespaceCount
	for _, r := range visible {
		if n := len(out); n > 0 && out[n-1].Namespace == r.Namespace {
			out[n-1].Resources++
			continue
		}
		out = append(out, NamespaceCount{Namespace: r.Namespace, Resources: 1})
	}
	return out
}

// capNamespaces keeps the overviewNamespacesMax namespaces with the most
// visible resources, most first (ties by namespace name), and counts the
// rest. nil when nothing was left out.
func capNamespaces(namespaces []NamespaceCount) ([]NamespaceCount, *OtherNamespaces) {
	sorted := slices.Clone(namespaces)
	slices.SortFunc(sorted, func(a, b NamespaceCount) int {
		return cmp.Or(cmp.Compare(b.Resources, a.Resources), cmp.Compare(a.Namespace, b.Namespace))
	})
	if len(sorted) <= overviewNamespacesMax {
		return sorted, nil
	}
	other := &OtherNamespaces{Namespaces: len(sorted) - overviewNamespacesMax}
	for _, nc := range sorted[overviewNamespacesMax:] {
		other.Resources += nc.Resources
	}
	return sorted[:overviewNamespacesMax], other
}

// overviewLargeSteps (OVERVIEW_LARGE): search instead of listing. The
// arguments list the largest namespace, a complete call the agent can make
// as it is.
func overviewLargeSteps(b *guidance.Steps, namespaces []NamespaceCount) {
	largest := namespaces[0]
	for _, nc := range namespaces[1:] {
		if nc.Resources > largest.Resources {
			largest = nc
		}
	}
	b.CallTool(guidance.ToolDescribe, map[string]any{guidance.ArgQuery: firstRunes(largest.Namespace, describeQueryMax)},
		"Find resources with describe and a query: a word of a resource, field or namespace name. These arguments list the largest namespace.")
}

// notGrantedSplit is the not-granted resources split by where they are: in
// the namespaces where the agent can read a resource (named, since it sees
// them) and in the others (only counted, never named).
type notGrantedSplit struct {
	inGranted int
	other     int
	// otherNamespaces is how many namespaces the agent has no grant in.
	otherNamespaces int
	// heldBack are the granted namespaces with something not granted, and
	// granted all of them, by name.
	heldBack, granted []string
	noun              agentstore.Noun
}

func splitNotGranted(visible []NamespaceCount, ungranted agentstore.NotGranted) notGrantedSplit {
	s := notGrantedSplit{noun: ungranted.Namespace}
	if s.noun.One == "" {
		s.noun = agentstore.Noun{One: "namespace", Many: "namespaces"}
	}
	seen := make(map[string]bool, len(visible))
	for _, nc := range visible {
		seen[nc.Namespace] = true
		s.granted = append(s.granted, nc.Namespace)
		if n := ungranted.Namespaces[nc.Namespace]; n > 0 {
			s.inGranted += n
			s.heldBack = append(s.heldBack, nc.Namespace)
		}
	}
	for ns, n := range ungranted.Namespaces {
		if n > 0 && !seen[ns] {
			s.other += n
			s.otherNamespaces++
		}
	}
	return s
}

// namedNamespacesMax is how many namespaces a not-granted message names.
const namedNamespacesMax = 3

// namespaceList names up to three namespaces, or counts them.
func (s notGrantedSplit) namespaceList(names []string) string {
	switch {
	case len(names) == 1:
		return names[0]
	case len(names) <= namedNamespacesMax:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
	return fmt.Sprintf("the %d %s it can see", len(names), s.noun.Many)
}

// notGrantedSteps (NOT_GRANTED): the person tells the agent when it needs
// one of the resources; the setup page that basalt init links to lists them, so
// the agent never sees their names (D-1, D-7). The message names only
// namespaces the agent has a grant in, and counts the rest. No ASK_PERSON:
// platform namespaces are ungranted on every Supabase project.
func (ds *Service) notGrantedSteps(b *guidance.Steps, s notGrantedSplit) string {
	b.TellAgent("Tell the agent when it needs one of these resources: it gives you a link where you pick them.")
	where := func(other bool) string {
		w := fmt.Sprintf("%d %s", s.otherNamespaces, plural(s.otherNamespaces, s.noun.One, s.noun.Many))
		if other && len(s.granted) > 0 {
			w = fmt.Sprintf("%d other %s", s.otherNamespaces, plural(s.otherNamespaces, s.noun.One, s.noun.Many))
		}
		return w
	}
	resources := func(n int) string { return fmt.Sprintf("%d %s", n, plural(n, "resource", "resources")) }
	var msg string
	switch {
	case s.inGranted == 0:
		if len(s.granted) > 0 {
			msg = fmt.Sprintf("Everything in %s is granted. ", s.namespaceList(s.granted))
		}
		msg += fmt.Sprintf("%s in %s %s not granted to the agent.", resources(s.other), where(true), plural(s.other, "is", "are"))
	case s.other == 0:
		msg = fmt.Sprintf("%s in %s %s not granted to the agent.",
			resources(s.inGranted), s.namespaceList(s.heldBack), plural(s.inGranted, "is", "are"))
	default:
		msg = fmt.Sprintf("%s in %s and %d in %s are not granted to the agent.",
			resources(s.inGranted), s.namespaceList(s.heldBack), s.other, where(true))
	}
	return msg + " To give it one, tell the agent: it gives you a link where you pick the resources."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// describeNotFound is NOT_FOUND for a resource that does not exist and for
// one the agent cannot read: the same answer, so names cannot be probed.
func describeNotFound(resource string) error {
	return &toolresult.ToolError{Code: guidance.CodeNotFound, Message: fmt.Sprintf(
		"%q is not a resource this agent can read: it does not exist, or the agent has no access to it", firstRunes(resource, guidance.MaxTableChars))}
}

// describeNotFoundSteps are NOT_FOUND's steps for describe, all of them on
// every answer: search, ask, and basalt init, whose link opens the page
// where the person grants a resource.
func (ds *Service) describeNotFoundSteps(b *guidance.Steps, f guidance.Failure) string {
	b.CallTool(guidance.ToolDescribe, map[string]any{guidance.ArgQuery: ds.searchTerm(f.Arg(guidance.ArgResource))},
		"Search for the resource by name: it may be spelled differently or sit in another namespace.")
	b.AskPerson("Tell the person the resource was not found or is not granted to you, and ask whether you should have it.")
	b.TellAgent("Tell the agent to add the resource once you decide it should have it, or which resource to use instead.")
	b.AgentRunCommand(ds.core.Commands.Init(), "When the person tells you to add it, run this and show them the link it prints, where they grant the resource.")
	return "The agent asked for a resource it cannot see: it does not exist, or the agent may not read it. " +
		"An agent uses one database; a resource in another database needs its own agent. " +
		"To give the agent a resource, tell it: it gives you a link where you pick the resources."
}
