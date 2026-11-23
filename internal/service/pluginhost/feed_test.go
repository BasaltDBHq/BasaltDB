package pluginhost

import (
	"context"
	"errors"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// A call made for one registration of an entry fails UNAVAILABLE, unsent,
// once the entry was registered again (restarted, or started for other
// agents): what a reader read for the earlier registration never reaches
// the later one.
func TestCallOnRefusesAnotherRegistration(t *testing.T) {
	h := NewHost()
	e := notifierEntry("a")
	f := register(t, h, e)
	first, ok := h.Registration(e.Key)
	if !ok || first == 0 {
		t.Fatalf("registration = %v, %v", first, ok)
	}
	if err := h.CallOn(context.Background(), e.Key, first, []string{"a"}, "wire.detect", nil, nil); err != nil {
		t.Fatalf("call on the current registration: %v", err)
	}
	h.Unregister(e.Key)
	g := register(t, h, e)
	second, _ := h.Registration(e.Key)
	if second == first {
		t.Fatal("a new registration has a new value")
	}
	before := len(g.methods())
	err := h.CallOn(context.Background(), e.Key, first, []string{"a"}, "wire.detect", nil, nil)
	var ce *pluginmodel.CallError
	if !errors.As(err, &ce) || ce.Class != pluginmodel.ClassUnavailable {
		t.Fatalf("call on an earlier registration = %v", err)
	}
	if _, err := h.ObserveFeedOn(context.Background(), e.Key, first, "a", batch(1)); !errors.As(err, &ce) || ce.Class != pluginmodel.ClassUnavailable {
		t.Fatalf("feed.observe on an earlier registration = %v", err)
	}
	if len(g.methods()) != before {
		t.Fatal("nothing was sent")
	}
	_ = f
	if _, ok := h.Registration(pluginmodel.EntryKey{Name: "other", Instance: "default"}); ok {
		t.Fatal("an unknown entry has no registration")
	}
}
