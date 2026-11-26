package agent

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// DescribeOverview counts what the agent can see, lists it (up to 50
// resources) or its namespaces, and tells the person how to see what it
// cannot.
func (ds *Service) DescribeOverview(ctx context.Context) (Overview, error) {
	visible, notGranted, err := ds.store.Catalog.Resources(ctx)
	if err != nil {
		return Overview{}, err
	}
	lines, err := ds.store.Catalog.Structure(ctx)
	if err != nil {
		return Overview{}, err
	}
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
		o.PersonMessage = ds.notGrantedSteps(b, notGranted)
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

// notGrantedSteps (NOT_GRANTED): the person tells the agent when it needs
// one of the resources; the setup page that basalt init links to lists them, so
// the agent never sees their names (D-1, D-7). No ASK_PERSON: platform
// namespaces are ungranted on every Supabase project.
func (ds *Service) notGrantedSteps(b *guidance.Steps, notGranted int) string {
	b.TellAgent("Tell the agent when it needs one of these resources: it gives you a link where you pick them.")
	return fmt.Sprintf("%d %s in this database %s not granted to the agent, so it cannot see %s. "+
		"To give it one, tell the agent: it gives you a link where you pick the resources.",
		notGranted, plural(notGranted, "resource", "resources"), plural(notGranted, "is", "are"), plural(notGranted, "it", "them"))
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
