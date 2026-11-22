package approval_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
)

func deleteLine(table string, id int, cascaded bool) string {
	return fmt.Sprintf(`{"op": "DELETE", "key": {"id": %d}, "old": {"id": %d}, "set": null, "table": %q, "cascaded": %t}`, id, id, table, cascaded)
}

func redactedLine(op, table string, cascaded bool) string {
	return fmt.Sprintf(`{"op": %q, "table": %q, "rowHash": %q, "cascaded": %t, "redacted": true}`, op, table, strings.Repeat("cd", sha256.Size), cascaded)
}

func updateLine(table string, id int, cascaded bool) string {
	return fmt.Sprintf(`{"op": "UPDATE", "key": {"id": %d}, "old": {"id": %d, "lead_id": 3}, "set": null, "table": %q, "cascaded": %t}`, id, id, table, cascaded)
}

func insertLine(table string) string {
	return fmt.Sprintf(`{"op": "INSERT", "key": null, "old": null, "set": {"name": "x"}, "table": %q, "cascaded": false}`, table)
}

func repeatLine(n int, line func(i int) string) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, line(i))
	}
	return out
}

// summaryCase is a held write's lines and the headline every surface shows
// for them. The cases are shared with the page (web/lib/summary.test.mjs).
type summaryCase struct {
	Name         string   `json:"name"`
	Lines        []string `json:"lines"`
	Headline     string   `json:"headline"`
	CascadedRows int      `json:"cascadedRows"`
}

func summaryCases() []summaryCase {
	invoices := repeatLine(28, func(i int) string { return deleteLine("public.invoices", 100+i, true) })
	payments := repeatLine(2, func(int) string { return redactedLine("DELETE", "public.payments", true) })
	customer := []string{deleteLine("public.customers", 7, false)}
	return []summaryCase{
		{
			Name:     "no cascade",
			Lines:    repeatLine(15, func(i int) string { return updateLine("public.leads", 21+i, false) }),
			Headline: "Update 15 rows in public.leads",
		},
		{
			Name:         "cascades, one table hidden",
			Lines:        append(append(append([]string{}, customer...), invoices...), payments...),
			Headline:     "Delete 1 row in public.customers + 30 cascaded rows (public.invoices 28, public.payments 2 [values hidden])",
			CascadedRows: 30,
		},
		{
			Name:         "the fixture request",
			Lines:        previewLines(),
			Headline:     "Delete 1 row in public.leads + 2 cascaded rows (public.lead_notes 1, public.note_tags 1 [values hidden])",
			CascadedRows: 2,
		},
		{
			Name:         "a cascade of another operation",
			Lines:        []string{deleteLine("public.leads", 3, false), deleteLine("public.leads", 4, false), updateLine("public.lead_owner", 1, true)},
			Headline:     "Delete 2 rows in public.leads + 1 cascaded row (public.lead_owner 1 updated)",
			CascadedRows: 1,
		},
		{
			Name:     "an upsert on a hidden table",
			Lines:    []string{insertLine("public.leads"), redactedLine("UPDATE", "public.leads", false), insertLine("public.leads")},
			Headline: "Insert 2 rows in public.leads, update 1 row in public.leads [values hidden]",
		},
	}
}

func TestSummaryHeadline(t *testing.T) {
	t.Parallel()
	for _, c := range summaryCases() {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			s, err := approval.SummarizeText(c.Lines)
			require.NoError(t, err)
			require.Equal(t, c.Headline, s.Headline())
			require.Equal(t, c.CascadedRows, s.CascadedRows())
		})
	}
}

func TestSummarizeTextRefusesABadLine(t *testing.T) {
	t.Parallel()
	_, err := approval.SummarizeText([]string{`{"op": "MERGE", "table": "t", "cascaded": false}`})
	require.ErrorIs(t, err, approval.ErrInvalid)
}
