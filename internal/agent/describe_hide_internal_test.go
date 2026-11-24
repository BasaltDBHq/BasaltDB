package agent

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// docDisplay is a store-rendered feature: it names the fields it covers.
type docDisplay struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// customersDoc is a collection in a store that is not Postgres: a field the
// agent cannot read (ssn), one classed SECRET (token), a search index that
// names token, a link to a collection the agent cannot read, and a
// computed field over ssn.
func customersDoc() (agentstore.Detail, []pii.Class) {
	ref := func(s string) agentstore.FieldRef { return agentstore.FieldRef("customers/" + s) }
	d := agentstore.Detail{
		Resource: agentstore.Resource{Ref: "app.customers", Namespace: "app", Name: "customers", Kind: "COLLECTION", Actions: []action.Op{action.OpSelect}},
		Fields: []agentstore.Field{
			{Ref: ref("_id"), Name: "_id", Type: "objectId", Readable: true},
			{Ref: ref("ssn"), Name: "ssn", Type: "string", Nullable: true},
			{Ref: ref("token"), Name: "token", Type: "string", Readable: true},
			{
				Ref: ref("masked"), Name: "masked", Type: "string", Readable: true, ReadsFrom: []agentstore.FieldRef{ref("ssn")},
				Display: map[string]any{"computed": "concat(ssn)"}, Masked: map[string]any{"computed": nil},
			},
			{Ref: ref("email"), Name: "email", Type: "string", Readable: true, Display: map[string]any{"computed": nil}},
		},
		Identity: []agentstore.FieldRef{ref("_id")},
		Groups:   []string{"searchIndexes", "links"},
		Features: []agentstore.Feature{
			{
				Group: "searchIndexes", Touches: []agentstore.FieldRef{ref("email")}, Visible: true,
				Display: docDisplay{Name: "by_email", Fields: []string{"email"}},
			},
			{
				Group: "searchIndexes", Touches: []agentstore.FieldRef{ref("email"), ref("token")}, Visible: true,
				Display: docDisplay{Name: "by_token_idx", Fields: []string{"email", "token"}},
			},
			{
				Group: "links", Touches: []agentstore.FieldRef{ref("_id")}, Visible: false,
				Display: docDisplay{Name: "audit_link", Fields: []string{"_id"}},
			},
		},
		Flags: map[string]any{"sharded": true},
		Stats: map[string]any{"documents": 3},
	}
	classes := []pii.Class{
		{Class: guardmodel.ClassPublic}, {}, {Class: guardmodel.ClassSecret}, {}, {Class: guardmodel.ClassIdentifier, EntityType: "EMAIL"},
	}
	return d, classes
}

func TestHideFieldsHidesFeaturesThatTouchAHiddenField(t *testing.T) {
	t.Parallel()
	d, classes := customersDoc()
	detail, err := hideFields(d, classes)
	require.NoError(t, err)
	raw, err := json.Marshal(Resource{Resource: "app.customers", Detail: &detail})
	require.NoError(t, err)
	for _, hidden := range []string{"ssn", "token", "by_token_idx", "audit_link"} {
		require.NotContains(t, string(raw), hidden, "a hidden name never shows")
	}

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	require.EqualValues(t, 2, m["hiddenFields"], "the unreadable field and the SECRET one")
	require.Equal(t, []any{map[string]any{"name": "by_email", "fields": []any{"email"}}}, m["searchIndexes"])
	require.EqualValues(t, 1, m["hiddenSearchIndexes"], "the index whose display names the SECRET field")
	require.Equal(t, []any{}, m["links"], "a listed group is present when all its features are hidden")
	require.EqualValues(t, 1, m["hiddenLinks"], "a feature that is not Visible is hidden and counted")
	require.Equal(t, []any{"_id"}, m["primaryKey"])
	require.EqualValues(t, 0, m["hiddenKeys"])
	require.Equal(t, true, m["sharded"])
	require.NotContains(t, m, "stats", "stats are added after the fingerprint, by DescribeResource")

	fields := m["fields"].([]any)
	require.Len(t, fields, 3)
	masked := fields[1].(map[string]any)
	require.Equal(t, "masked", masked["name"])
	require.Equal(t, true, masked["expressionHidden"])
	require.Contains(t, masked, "computed", "the masked display is shown in place of the display")
	require.Nil(t, masked["computed"])
	email := fields[2].(map[string]any)
	require.Equal(t, map[string]any{"class": "IDENTIFIER", "entityType": "EMAIL"}, email["pii"])
}

func TestHideFieldsCountsAnIdentityOnAHiddenField(t *testing.T) {
	t.Parallel()
	d, classes := customersDoc()
	d.Identity = append(d.Identity, d.Fields[2].Ref)
	detail, err := hideFields(d, classes)
	require.NoError(t, err)
	require.Empty(t, detail.PrimaryKey)
	require.Equal(t, 1, detail.HiddenKeys)
}

func TestHideFieldsListsAGroupOnlyAFeatureNames(t *testing.T) {
	t.Parallel()
	d, classes := customersDoc()
	d.Groups = nil
	detail, err := hideFields(d, classes)
	require.NoError(t, err)
	keys := make([]string, 0, len(detail.Features))
	for _, g := range detail.Features {
		keys = append(keys, g.Key)
	}
	require.Equal(t, []string{"searchIndexes", "links"}, keys, "no feature is dropped")

	d.Features[0].Group = ""
	_, err = hideFields(d, classes)
	require.ErrorIs(t, err, errUnnamedGroup)
}

func TestFieldDisplayMustBeAnObject(t *testing.T) {
	t.Parallel()
	_, err := json.Marshal(Field{Name: "x", Display: "not an object"})
	require.ErrorIs(t, err, errDisplayNotObject)
}

// TestResourceFingerprintReadsTheStableForm: what a feature's Stable form
// leaves out, and stats, do not move the fingerprint.
func TestResourceFingerprintReadsTheStableForm(t *testing.T) {
	t.Parallel()
	fp := func(scans int, docs int) string {
		d, classes := customersDoc()
		d.Features[0].Display = map[string]any{"name": "by_email", "scans": scans}
		d.Features[0].Stable = map[string]any{"name": "by_email", "scans": 0}
		d.Stats = map[string]any{"documents": docs}
		detail, err := hideFields(d, classes)
		require.NoError(t, err)
		detail.Stats = d.Stats
		out, err := resourceFingerprint(Resource{Resource: "app.customers", Detail: &detail}, "")
		require.NoError(t, err)
		return out
	}
	require.Equal(t, fp(1, 1), fp(99, 50))
}

// TestHideFieldsFailsWhenClassesAreShort: a field with no class is never
// taken as not SECRET; describe fails closed.
func TestHideFieldsFailsWhenClassesAreShort(t *testing.T) {
	t.Parallel()
	d, classes := customersDoc()
	_, err := hideFields(d, classes[:len(classes)-1])
	require.ErrorIs(t, err, errClassesShort)
	_, err = hideFields(d, nil)
	require.ErrorIs(t, err, errClassesShort)
}

// TestHideFieldsRefusesAStoreKeyTheAnswerHas: a group, hidden count, flag
// or display member the answer already writes, or two of the store's own
// keys that meet, is an engine error, never a duplicate or shadowed key.
func TestHideFieldsRefusesAStoreKeyTheAnswerHas(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		edit func(*agentstore.Detail)
	}{
		{"flag kind", func(d *agentstore.Detail) { d.Flags["kind"] = "x" }},
		{"flag stats, written only after the fingerprint", func(d *agentstore.Detail) { d.Flags["stats"] = 1 }},
		{"flag primaryKey, written only when there is one", func(d *agentstore.Detail) { d.Flags["primaryKey"] = []string{"ssn"} }},
		{"group fields", func(d *agentstore.Detail) { d.Groups = append(d.Groups, "fields") }},
		{"group keys counts into hiddenKeys", func(d *agentstore.Detail) { d.Features[0].Group = "keys" }},
		{"flag is a group", func(d *agentstore.Detail) { d.Flags["links"] = true }},
		{"flag is a hidden count", func(d *agentstore.Detail) { d.Flags["hiddenLinks"] = 0 }},
		{"display member name", func(d *agentstore.Detail) { d.Fields[4].Display = map[string]any{"name": "other"} }},
		{"masked member pii", func(d *agentstore.Detail) { d.Fields[3].Masked = map[string]any{"pii": nil} }},
		{"display member twice", func(d *agentstore.Detail) {
			d.Fields[4].Display = json.RawMessage(`{"computed":1,"computed":2}`)
		}},
	} {
		d, classes := customersDoc()
		tc.edit(&d)
		_, err := hideFields(d, classes)
		require.ErrorIs(t, err, errStoreKey, tc.name)
	}
}

// TestReservedKeysAreTheAnswersKeys keeps resourceKeys and fieldKeys equal
// to the keys the answer writes itself, every optional one set.
func TestReservedKeysAreTheAnswersKeys(t *testing.T) {
	t.Parallel()
	p := writePolicy
	r := Resource{
		Form: FormResource, Resource: "app.t", Fingerprint: "f", Unchanged: true,
		Detail: &ResourceDetail{Kind: "TABLE", Comment: "c", PrimaryKey: []string{"id"}, Stats: map[string]any{}, Policy: &p},
	}
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	require.ElementsMatch(t, resourceKeys, keysOf(m))

	raw, err = json.Marshal(Field{Name: "x", ExpressionHidden: true, Comment: "c"})
	require.NoError(t, err)
	m = nil
	require.NoError(t, json.Unmarshal(raw, &m))
	require.ElementsMatch(t, fieldKeys, keysOf(m))
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
