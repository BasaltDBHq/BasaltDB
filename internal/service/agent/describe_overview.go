package agent

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// DescribeOverview counts what the agent can see, lists it (up to 50
// tables) or its schemas, and tells the person how to see what it cannot.
func (s *Service) DescribeOverview(ctx context.Context) (Overview, error) {
	visible, notGranted, err := s.deps.Describe.Catalog.Relations(ctx)
	if err != nil {
		return Overview{}, err
	}
	lines, err := s.deps.Describe.Catalog.Structure(ctx)
	if err != nil {
		return Overview{}, err
	}
	pii, err := s.deps.Describe.Classes.CatalogFingerprint(ctx)
	if err != nil {
		return Overview{}, err
	}
	limits := s.deps.Describe.Catalog.Limits()
	o := Overview{
		Store:       StoreInfo{Kind: string(s.deps.Core.Store.Kind()), Database: s.deps.Describe.Catalog.Database(), Host: s.deps.Describe.Catalog.Host()},
		Fingerprint: catalogFingerprint(lines, notGranted, pii),
		Counts:      Counts{Tables: len(visible), NotGranted: notGranted},
		Update:      s.updateInfo(),
		Limits: OverviewLimits{
			ReadRowLimit: limits.ReadRowLimit, StatementTimeoutMs: limits.StatementTimeout.Milliseconds(), WritePolicy: writePolicy,
		},
	}
	schemas := schemaCounts(visible)
	o.Counts.Schemas = len(schemas)
	b := guidance.NewSteps()
	switch {
	case len(visible) > overviewInlineMax:
		o.Schemas, o.OtherSchemas = capSchemas(schemas)
		overviewLargeSteps(b, o.Schemas)
	default:
		o.Resources = make([]SearchItem, 0, len(visible))
		for _, r := range visible {
			o.Resources = append(o.Resources, searchItem(r, ""))
		}
	}
	if notGranted > 0 {
		o.PersonMessage = s.notGrantedSteps(b, notGranted)
	}
	if o.Schemas == nil && notGranted == 0 {
		return o, nil
	}
	if o.NextSteps, err = b.Build(); err != nil {
		return Overview{}, err
	}
	return o, nil
}

// schemaCounts counts the visible tables of each schema, by schema name.
func schemaCounts(visible []CatalogRelation) []SchemaCount {
	var out []SchemaCount
	for _, r := range visible {
		if n := len(out); n > 0 && out[n-1].Schema == r.Schema {
			out[n-1].Tables++
			continue
		}
		out = append(out, SchemaCount{Schema: r.Schema, Tables: 1})
	}
	return out
}

// capSchemas keeps the overviewSchemasMax schemas with the most visible
// tables, most first (ties by schema name), and counts the rest. nil when
// nothing was left out.
func capSchemas(schemas []SchemaCount) ([]SchemaCount, *OtherSchemas) {
	sorted := slices.Clone(schemas)
	slices.SortFunc(sorted, func(a, b SchemaCount) int {
		return cmp.Or(cmp.Compare(b.Tables, a.Tables), cmp.Compare(a.Schema, b.Schema))
	})
	if len(sorted) <= overviewSchemasMax {
		return sorted, nil
	}
	other := &OtherSchemas{Schemas: len(sorted) - overviewSchemasMax}
	for _, sc := range sorted[overviewSchemasMax:] {
		other.Tables += sc.Tables
	}
	return sorted[:overviewSchemasMax], other
}

// overviewLargeSteps (OVERVIEW_LARGE): search instead of listing. The
// arguments list the largest schema, a complete call the agent can make as
// it is.
func overviewLargeSteps(b *guidance.Steps, schemas []SchemaCount) {
	largest := schemas[0]
	for _, sc := range schemas[1:] {
		if sc.Tables > largest.Tables {
			largest = sc
		}
	}
	b.CallTool(toolDescribe, map[string]any{argQuery: firstRunes(largest.Schema, describeQueryMax)},
		"Find tables with describe and a query: a word of a table, column or schema name. These arguments list the largest schema.")
}

// notGrantedSteps (NOT_GRANTED): the person tells the agent when it needs
// one of the tables; the setup page that basalt init links to lists them, so
// the agent never sees their names (D-1, D-7). No ASK_PERSON: platform
// schemas are ungranted on every Supabase project.
func (s *Service) notGrantedSteps(b *guidance.Steps, notGranted int) string {
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
		"%q is not a table this agent can read: it does not exist, or the agent has no access to it", firstRunes(resource, maxTableChars))}
}

// describeNotFoundSteps are NOT_FOUND's steps for describe, all of them on
// every answer: search, ask, and basalt init, whose link opens the page
// where the person grants a table.
func (s *Service) describeNotFoundSteps(b *guidance.Steps, f failure) string {
	b.CallTool(toolDescribe, map[string]any{argQuery: searchTerm(f.arg(argResource))},
		"Search for the table by name: it may be spelled differently or sit in another schema.")
	b.AskPerson("Tell the person the table was not found or is not granted to you, and ask whether you should have it.")
	b.TellAgent("Tell the agent to add the table once you decide it should have it, or which table to use instead.")
	b.AgentRunCommand(s.deps.Core.Commands.Init(), "When the person tells you to add it, run this and show them the link it prints, where they grant the table.")
	return "The agent asked for a table it cannot see: it does not exist, or the agent may not read it. " +
		"An agent uses one database; a table in another database needs its own agent. " +
		"To give the agent a table, tell it: it gives you a link where you pick the tables."
}
