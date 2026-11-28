package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

const pickLink = " To give it one, tell the agent: it gives you a link where you pick the resources."

var schemaNoun = agentstore.Noun{One: "schema", Many: "schemas"}

// TestNotGrantedMessageSplitsByNamespace: the person hears how much is held
// back where the agent has a grant, and only a count of the other namespaces,
// which are never named.
func TestNotGrantedMessageSplitsByNamespace(t *testing.T) {
	t.Parallel()
	other := map[string]int{"auth": 100, "storage": 90, "realtime": 14}
	cases := map[string]struct {
		visible    []NamespaceCount
		notGranted map[string]int
		want       string
	}{
		"none held back in its own namespace": {
			visible:    []NamespaceCount{{Namespace: "public", Resources: 1}},
			notGranted: other,
			want:       "Everything in public is granted. 204 resources in 3 other schemas are not granted to the agent." + pickLink,
		},
		"some held back": {
			visible:    []NamespaceCount{{Namespace: "public", Resources: 1}},
			notGranted: map[string]int{"public": 3, "auth": 100, "storage": 90, "realtime": 14},
			want:       "3 resources in public and 204 in 3 other schemas are not granted to the agent." + pickLink,
		},
		"only its own namespace": {
			visible:    []NamespaceCount{{Namespace: "public", Resources: 1}, {Namespace: "shop", Resources: 2}},
			notGranted: map[string]int{"public": 1},
			want:       "1 resource in public is not granted to the agent." + pickLink,
		},
		"one other namespace": {
			visible:    []NamespaceCount{{Namespace: "public", Resources: 1}},
			notGranted: map[string]int{"auth": 1},
			want:       "Everything in public is granted. 1 resource in 1 other schema is not granted to the agent." + pickLink,
		},
		"a grant in many namespaces": {
			visible:    []NamespaceCount{{Namespace: "a"}, {Namespace: "b"}, {Namespace: "c"}, {Namespace: "d"}},
			notGranted: map[string]int{"x": 2},
			want:       "Everything in the 4 schemas it can see is granted. 2 resources in 1 other schema are not granted to the agent." + pickLink,
		},
		"no grant at all": {
			notGranted: other,
			want:       "204 resources in 3 schemas are not granted to the agent." + pickLink,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ng := agentstore.NotGranted{Namespaces: c.notGranted, Namespace: schemaNoun}
			got := (&Service{}).notGrantedSteps(guidance.NewSteps(), splitNotGranted(c.visible, ng))
			require.Equal(t, c.want, got)
			require.NoError(t, guidance.CheckPersonMessage(got))
			for _, hidden := range []string{"auth", "storage", "realtime", "x"} {
				require.NotContains(t, got, hidden, "a namespace with no grant is never named")
			}
		})
	}
}

// TestNotGrantedMessageUsesNeutralWordsWithoutAStoreNoun: a store that gives
// no word is read as "namespace".
func TestNotGrantedMessageUsesNeutralWordsWithoutAStoreNoun(t *testing.T) {
	t.Parallel()
	split := splitNotGranted([]NamespaceCount{{Namespace: "shop"}}, agentstore.NotGranted{Namespaces: map[string]int{"x": 5, "y": 1}})
	require.Equal(t, 6, split.other)
	require.Equal(t, 2, split.otherNamespaces)
	got := (&Service{}).notGrantedSteps(guidance.NewSteps(), split)
	require.Contains(t, got, "6 resources in 2 other namespaces are not granted")
}
