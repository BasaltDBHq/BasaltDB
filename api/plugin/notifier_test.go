package plugincontract_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/testkit/contractdoc"
)

// The notifier messages (CONTRACT.md, Plugins, The feed.observe and
// approval.deliver messages): feed/1 carries a CloudEvents JSON batch of one
// agent's ledger events, deliver/1 one notice as a CloudEvent.

type testCloudEvent struct {
	ID      string          `json:"id"`
	Source  string          `json:"source"`
	Type    string          `json:"type"`
	Subject string          `json:"subject"`
	Data    json.RawMessage `json:"data"`
}

type testFeedData struct {
	InstallID string `json:"installId"`
	Seq       int64  `json:"seq"`
	Agent     string `json:"agent"`
	AfterSeq  *int64 `json:"afterSeq"`
}

type testFeedRequest struct {
	Agent  string           `json:"agent"`
	Events []testCloudEvent `json:"events"`
}

// skippedType is the skipped-ahead marker's type.
const skippedType = "dev.basaltdb.feed.skipped"

func feedEvents(raw []byte) (string, []testCloudEvent, []testFeedData, error) {
	var r testFeedRequest
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", nil, nil, err
	}
	data := make([]testFeedData, len(r.Events))
	for i, e := range r.Events {
		if err := json.Unmarshal(e.Data, &data[i]); err != nil {
			return "", nil, nil, err
		}
	}
	return r.Agent, r.Events, data, nil
}

// ruleFeedOneAgent: every event of a call is the agent the call names, in
// subject and in data.agent (CONTRACT.md, Per-agent scope).
var ruleFeedOneAgent = rule{"feedOneAgent", func(raw []byte) error {
	agent, events, data, err := feedEvents(raw)
	if err != nil {
		return err
	}
	for i, e := range events {
		if e.Subject != agent || data[i].Agent != agent {
			return fmt.Errorf("event %d is not of agent %s", i, agent)
		}
	}
	return nil
}}

// ruleFeedAscending: the events of a call are in ascending seq, chain order.
var ruleFeedAscending = rule{"feedAscending", func(raw []byte) error {
	_, _, data, err := feedEvents(raw)
	if err != nil {
		return err
	}
	for i := 1; i < len(data); i++ {
		if data[i].Seq <= data[i-1].Seq {
			return fmt.Errorf("event %d is not after event %d", i, i-1)
		}
	}
	return nil
}}

// ruleFeedIDs: source is urn:uuid:<installId>, and id is <installId>:<seq>,
// or <installId>:skipped:<afterSeq>:<seq> for the marker, so a redelivery
// carries the same source and id.
var ruleFeedIDs = rule{"feedIDs", func(raw []byte) error {
	_, events, data, err := feedEvents(raw)
	if err != nil {
		return err
	}
	for i, e := range events {
		d := data[i]
		want := fmt.Sprintf("%s:%d", d.InstallID, d.Seq)
		if e.Type == skippedType {
			if d.AfterSeq == nil {
				return errors.New("a skipped marker without afterSeq")
			}
			want = fmt.Sprintf("%s:skipped:%d:%d", d.InstallID, *d.AfterSeq, d.Seq)
		}
		if e.ID != want || e.Source != "urn:uuid:"+d.InstallID {
			return fmt.Errorf("event %d: id %s, source %s, want id %s", i, e.ID, e.Source, want)
		}
	}
	return nil
}}

// ruleDeliverOneAgent: a notice is of the agent its call names.
var ruleDeliverOneAgent = rule{"deliverOneAgent", func(raw []byte) error {
	var r struct {
		Agent string         `json:"agent"`
		Event testCloudEvent `json:"event"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	var d struct {
		Agent string `json:"agent"`
	}
	if err := json.Unmarshal(r.Event.Data, &d); err != nil {
		return err
	}
	if r.Event.Subject != r.Agent || d.Agent != r.Agent {
		return fmt.Errorf("the notice is not of agent %s", r.Agent)
	}
	return nil
}}

// forbiddenKeys are ledger detail keys that hold a value, a statement, an
// intent, a refusal message, a passkey or another agent's name. None may
// appear at any depth of an event or a notice.
var forbiddenKeys = []string{
	"intent", "statement", "params", "reason", "before", "after", "key", "rowChanges", "rowsHash",
	"credentialId", "relayedBy", "select", "oldSelect", "droppedSelect", "binding", "note", "skipped", "lines",
}

func findKey(v any, keys []string) (string, bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if slices.Contains(keys, k) {
				return k, true
			}
			if found, ok := findKey(child, keys); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range x {
			if found, ok := findKey(child, keys); ok {
				return found, true
			}
		}
	}
	return "", false
}

// TestNotifierSamplesHoldNoValues: no valid feed or deliver sample carries a
// key that names a value, a statement, an intent, a refusal message or a
// passkey, at any depth.
func TestNotifierSamplesHoldNoValues(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{"valid-feed-*.json", "valid-deliver-*.json"} {
		files, err := filepath.Glob(filepath.Join("testdata", pattern))
		require.NoError(t, err)
		require.NotEmpty(t, files, pattern)
		for _, f := range files {
			raw, err := os.ReadFile(f)
			require.NoError(t, err)
			var v any
			require.NoError(t, json.Unmarshal(raw, &v), f)
			k, found := findKey(v, forbiddenKeys)
			require.False(t, found, "%s carries %s", f, k)
		}
	}
}

// checkInstallID is the install id of the samples basalt plugin check sends:
// no install has it, so a plugin can tell a sample from a real event.
const checkInstallID = "00000000-0000-0000-0000-000000000000"

// TestCheckSamples: the samples basalt plugin check sends hold no store
// data: the zero install id, and the resource basalt_check.sample only.
// Each sample names it at least once (a headline with a middle dot), so the
// check always has a name to compare.
func TestCheckSamples(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"valid-feed-request-check-sample.json", "valid-deliver-request-check-sample.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", f))
		require.NoError(t, err)
		text := string(raw)
		require.NotContains(t, text, "http", "%s: a sample carries no link", f)
		for _, src := range regexp.MustCompile(`"source": "([^"]+)"`).FindAllStringSubmatch(text, -1) {
			require.Equal(t, "urn:uuid:"+checkInstallID, src[1], f)
		}
		// A headline shows the dot of a name as a middle dot.
		names := regexp.MustCompile(`(?:"resource": "|in )([a-z_]+)[.\x{00B7}]([a-z_]+)`).FindAllStringSubmatch(text, -1)
		require.NotEmpty(t, names, "%s: a sample names its resource", f)
		for _, name := range names {
			require.Equal(t, "basalt_check.sample", name[1]+"."+name[2], f)
		}
	}
}

// TestNotifierNamesInContract: every CloudEvents type, notice kind and
// instruction sentence the schemas allow is written in CONTRACT.md word for
// word, and the contract names no other type under the prefix in code
// spans.
func TestNotifierNamesInContract(t *testing.T) {
	t.Parallel()
	contract, err := contractdoc.Read()
	require.NoError(t, err)
	text := string(contract)

	var allowed []string
	for _, ref := range []struct{ file, pointer string }{
		{"protocol/feed.schema.json", "#/$defs/event/properties/type"},
		{"protocol/deliver.schema.json", "#/$defs/event/properties/type"},
		{"protocol/deliver.schema.json", "#/$defs/notice/properties/kind"},
		{"protocol/deliver.schema.json", "#/$defs/notice/properties/instruction"},
		{"protocol/deliver.schema.json", "#/$defs/notice/properties/linkOpens"},
	} {
		values := schemaEnum(t, ref.file, ref.pointer)
		require.NotEmpty(t, values, ref.pointer)
		for _, v := range values {
			require.True(t, strings.Contains(text, v), "CONTRACT.md does not state %s", v)
		}
		allowed = append(allowed, values...)
	}
	for _, m := range regexp.MustCompile("`(dev\\.basaltdb\\.[a-z.]*[a-z])`").FindAllStringSubmatch(text, -1) {
		require.Contains(t, allowed, m[1], "CONTRACT.md names %s, which no schema allows", m[1])
	}
}

func schemaEnum(t *testing.T, file, pointer string) []string {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	var node any
	require.NoError(t, json.Unmarshal(raw, &node))
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "#/"), "/") {
		obj, ok := node.(map[string]any)
		require.True(t, ok, "%s %s", file, pointer)
		node = obj[part]
	}
	obj, ok := node.(map[string]any)
	require.True(t, ok, "%s %s", file, pointer)
	list, ok := obj["enum"].([]any)
	require.True(t, ok, "%s %s has no enum", file, pointer)
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		require.True(t, ok)
		out = append(out, s)
	}
	return out
}

// typePrefix is the reverse-DNS prefix of every type the engine emits: the
// engine's own, never the Vault's (CONTRACT.md, Notifier messages).
const typePrefix = "dev.basaltdb."

// TestNotifierTypeNames: every type is under the engine's prefix, names no
// hook but the skipped marker's feed, and no notice type is a feed type.
func TestNotifierTypeNames(t *testing.T) {
	t.Parallel()
	feed := schemaEnum(t, "protocol/feed.schema.json", "#/$defs/event/properties/type")
	notice := schemaEnum(t, "protocol/deliver.schema.json", "#/$defs/event/properties/type")
	for _, typ := range append(slices.Clone(feed), notice...) {
		require.True(t, strings.HasPrefix(typ, typePrefix), typ)
		require.NotContains(t, typ, "basaltvault", typ)
		require.NotContains(t, typ, ".notice.", typ)
		if typ != skippedType {
			require.NotContains(t, typ, ".feed.", typ)
		}
	}
	for _, typ := range notice {
		require.NotContains(t, feed, typ)
	}
}
