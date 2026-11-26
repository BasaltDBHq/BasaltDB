package storeproof_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// The PII domain on the same store, through its ports only. Known limit,
// stated and not tested: the observer and the scan's caller read top-level
// values only. The scan reaches a nested field because the store's reader
// walks its own path (customers#contact.email); a PII value inside a nested
// value of a result the agent reads is not seen until a result field
// carries a path, designed with the first real document store.

// instant is a scan's sleep that never waits.
func instant(context.Context, time.Duration) error { return nil }

// newScan is a scanner over the store's classes and reader, into a new
// dictionary.
func newScan(t *testing.T, h *harness) (*pii.Scanner, *corepii.FuseDictionary, *corepii.Keys) {
	t.Helper()
	dict, keys := newDictionary(t)
	src := pii.ScanSource{Agent: memAgent, Map: pii.NewMap(h.logger), Classes: h.store, Fields: memFields{h.store}}
	return pii.NewScanner(dict, []pii.ScanSource{src}, pii.ScanOptions{PageRows: 5, Sleep: instant}, h.logger), dict, keys
}

func hasEmail(dict *corepii.FuseDictionary, keys *corepii.Keys, v string) bool {
	return dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, v, ""))
}

// The scanner builds and commits a dictionary from the IDENTIFIER fields,
// nested ones by the store's path; a collection that is gone or too slow is
// skipped; any other error keeps the previous dictionary.
func TestMemoryStoreScanCommitsADictionary(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.pii.gone["archive"], h.store.pii.slow["events"] = true, true
	scan, dict, keys := newScan(t, h)

	res, err := scan.Cycle(context.Background())
	require.NoError(t, err)
	require.Equal(t, 3, res.Columns, "customers' email, alias and contact.email")
	require.Equal(t, 2, res.Skipped, "the gone collection and the slow one")
	require.EqualValues(t, memHeldOver+3, res.Rows)
	for _, v := range []string{"c05@example.com", "c05.alias@example.com", "c05.home@example.com"} {
		require.True(t, hasEmail(dict, keys, v), v)
	}
	require.False(t, hasEmail(dict, keys, `"c05.alias@example.com"`), "a JSON string is unquoted")
	require.Contains(t, h.log.String(), "the agent can no longer read it")
	require.Contains(t, h.log.String(), "a full read exceeds the statement timeout")

	h.store.seed(colCustomers, map[string]any{"_id": "c99", "email": "c99@example.com"})
	h.store.mu.Lock()
	h.store.pii.broken["customers"] = true
	h.store.mu.Unlock()
	_, err = scan.Cycle(context.Background())
	require.ErrorIs(t, err, errBroken)
	require.True(t, hasEmail(dict, keys, "c05@example.com"), "the previous dictionary stays")
	require.False(t, hasEmail(dict, keys, "c99@example.com"), "no part of the failed scan was committed")
}

// The class map resolves the store's refs, reloads once per unknown
// collection per tick, and gives an empty ref no class; describe and its
// search never name or match a SECRET field.
func TestMemoryStoreClassMapAndSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t)
	m := pii.NewMap(h.logger)

	got, err := m.Resolve(ctx, h.store, []agentstore.FieldRef{"customers#contact.email", "", "orders#status"})
	require.NoError(t, err)
	require.Equal(t, pii.Class{Namespace: "shop", Resource: "customers", Field: "contact.email", Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail}, got[0])
	require.Equal(t, pii.Class{}, got[1], "a computed value has no class")
	require.Equal(t, pii.Unclassified, got[2])
	require.Equal(t, 2, h.store.snapshots(), "the first load, then one reload for the unknown collection")

	_, err = m.Resolve(ctx, h.store, []agentstore.FieldRef{"orders#status"})
	require.NoError(t, err)
	require.Equal(t, 2, h.store.snapshots(), "once per collection per tick")

	reloaded, err := m.Tick(ctx, h.store)
	require.NoError(t, err)
	require.False(t, reloaded, "the marks did not move")
	h.store.classify(fieldClass(colOrders, "status", guardmodel.ClassPublic, ""))
	_, err = m.Resolve(ctx, h.store, []agentstore.FieldRef{"orders#status"})
	require.NoError(t, err)
	require.Equal(t, 3, h.store.snapshots(), "a new tick may reload for it once more")
	got, err = m.Resolve(ctx, h.store, []agentstore.FieldRef{"orders#status"})
	require.NoError(t, err)
	require.Equal(t, guardmodel.ClassPublic, got[0].Class)

	r, err := h.agent.DescribeResource(ctx, colCustomers, "")
	require.NoError(t, err)
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "ssn", "describe never names a SECRET field")
	var shown map[string]any
	require.NoError(t, json.Unmarshal(raw, &shown))
	require.EqualValues(t, 1, shown["hiddenFields"])

	for q, want := range map[string]int{"ssn": 0, "email": 1} {
		page, err := h.agent.DescribeSearch(ctx, agent.DescribeSearchParams{Query: q, Params: pagination.Params{Limit: 10}})
		require.NoError(t, err)
		require.Len(t, page.Items, want, q)
	}
	require.Contains(t, h.store.pii.excluded, fieldRef(colCustomers, "ssn"), "the store is told never to match it")
}

// A value the agent reads, by query or in a write's returned documents,
// reaches the dictionary as the same text the scan adds, a JSON string
// included.
func TestMemoryStoreValuesReachTheDictionaryAsTheScanAddsThem(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t)
	run, err := h.agent.StartRun(ctx, "read and fix c02", uuid.Nil)
	require.NoError(t, err)

	_, err = h.agent.Query(ctx, agent.QueryParams{Request: agentstore.Request{Text: findPro, Params: []any{"pro"}}, RunID: run.RunID})
	require.NoError(t, err)
	_, err = h.agent.Write(ctx, agent.WriteParams{Request: agentstore.Request{Text: upgradeTwo}, Intent: "move c02 to team", RunID: run.RunID})
	require.NoError(t, err)

	scan, dict, keys := newScan(t, h)
	_, err = scan.Cycle(ctx)
	require.NoError(t, err)
	for _, v := range []string{"c00.alias@example.com", "c02.alias@example.com", "c02@example.com"} {
		require.True(t, h.hasEmail(v), "read path: %s", v)
		require.True(t, hasEmail(dict, keys, v), "scan: %s", v)
	}
	for _, quoted := range []string{`"c00.alias@example.com"`, `"c02.alias@example.com"`} {
		require.False(t, h.hasEmail(quoted))
		require.False(t, hasEmail(dict, keys, quoted))
	}
}

// SuggestAll classifies a sampled email field by its kind, and a field whose
// documents hold more than one type is text, so it is still sampled.
func TestMemoryStoreSuggestsByKind(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cols := h.store.columns()
	results, err := pii.SuggestAll(context.Background(), cols, h.store.sample, pii.Options{})
	require.NoError(t, err)
	byName := map[string]pii.Result{}
	for _, r := range results {
		byName[r.Column.Name] = r
	}
	login := byName["login"]
	require.Equal(t, piistore.KindText, login.Column.Kind)
	require.Equal(t, guardmodel.ClassIdentifier, login.Suggestion.Class, "classified from its sample, not its name")
	require.Equal(t, guardmodel.EntityEmail, login.Suggestion.EntityType)

	tags := byName["tags"]
	require.Equal(t, piistore.KindText, tags.Column.Kind, "uncertain means text")
	require.Equal(t, "mixed", tags.Column.DataType)
	require.Contains(t, h.store.pii.sampled, "shop.customers.tags")
	require.False(t, slices.Contains(h.store.pii.sampled, "shop.customers.contact"), "an object is not sampled")
}

// Watch logs the fields the store reports unclassified.
func TestMemoryStoreWatchLogsAnUnclassifiedField(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	w := pii.NewWatch(memAgent, pii.NewMap(h.logger), pii.StoreSet{Classes: h.store}, h.logger)
	require.NoError(t, w.Tick(context.Background()))
	require.Contains(t, h.log.String(), "1 columns unclassified: shop.customers.note")
}
