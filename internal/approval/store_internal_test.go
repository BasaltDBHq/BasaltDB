package approval

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A store set with a nil port is refused when the service is built: the
// service reads the store only through its ports.
func TestNewRefusesAStoreSetWithANilPort(t *testing.T) {
	t.Parallel()
	full := func() StoreSet {
		var s struct{ Store }
		return StoreSet{Records: s, Holds: s, Proofs: s}
	}
	for name, breakIt := range map[string]func(*StoreSet){
		"Records": func(s *StoreSet) { s.Records = nil },
		"Holds":   func(s *StoreSet) { s.Holds = nil },
		"Proofs":  func(s *StoreSet) { s.Proofs = nil },
	} {
		set := full()
		breakIt(&set)
		require.PanicsWithValue(t, "approval: store set missing ports: "+name, func() {
			New(Core{}, set, &Deps{}, nil, nil)
		}, name)
	}
	require.PanicsWithValue(t, "approval: store set missing ports: Records, Holds, Proofs", func() {
		New(Core{}, StoreSet{}, &Deps{}, nil, nil)
	})
	require.NotPanics(t, func() { New(Core{}, full(), &Deps{}, nil, nil) })
}
