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
	visible, notGranted, err := ds.describe.Catalog.Resources(ctx)
	if err != nil {
		return Overview{}, err
	}
	lines, err := ds.describe.Catalog.Structure(ctx)
	if err != nil {
		return Overview{}, err
	}
	pii, err := ds.describe.Classes.CatalogFingerprint(ctx)
	if err != nil {
		return Overview{}, err
	}
	limits := ds.describe.Catalog.Limits()
	o := Overview{
		Store:       StoreInfo{Kind: string(ds.core.Store.Kind()), Database: ds.describe.Catalog.Database(), Host: ds.describe.Catalog.Host()},
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
			o.Resources = append(o.Resources, searchItem(r, ""))
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
		"Find tables with describe and a query: a word of a table, column or schema name. These arguments list the largest schema.")
}

// notGrantedSteps (NOT_GRANTED): the person tells the agent when it needs
// one of the tables; the setup page that basalt init links to lists them, so
// the agent never sees their names (D-1, D-7). No ASK_PERSON: platform
// schemas are ungranted on every Supabase project.
func (ds *Service) notGrantedSteps(b *guidance.Steps, notGranted int) string {
	b.TellAgent("Tell the agent when it needs one of these tables: it gives you a link where you pick them.")
	return fmt.Sprintf("%d %s in this database %s not granted to the agent, so it cannot see %s. "+
		"To give it one, tell the agent: it gives you a link where you pick the tables.",
		notGranted, plural(notGranted, "table", "tables"), plural(notGranted, "is", "are"), plural(notGranted, "it", "them"))
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
		"%q is not a table this agent can read: it does not exist, or the agent has no access to it", firstRunes(resource, guidance.MaxTableChars))}
}

// describeNotFoundSteps are NOT_FOUND's steps for describe, all of them on
// every answer: search, ask, and basalt init, whose link opens the page
// where the person grants a table.
func (ds *Service) describeNotFoundSteps(b *guidance.Steps, f guidance.Failure) string {
	b.CallTool(guidance.ToolDescribe, map[string]any{guidance.ArgQuery: searchTerm(f.Arg(guidance.ArgResource))},
		"Search for the table by name: it may be spelled differently or sit in another schema.")
	b.AskPerson("Tell the person the table was not found or is not granted to you, and ask whether you should have it.")
	b.TellAgent("Tell the agent to add the table once you decide it should have it, or which table to use instead.")
	b.AgentRunCommand(ds.core.Commands.Init(), "When the person tells you to add it, run this and show them the link it prints, where they grant the table.")
	return "The agent asked for a table it cannot see: it does not exist, or the agent may not read it. " +
		"An agent uses one database; a table in another database needs its own agent. " +
		"To give the agent a table, tell it: it gives you a link where you pick the tables."
}
