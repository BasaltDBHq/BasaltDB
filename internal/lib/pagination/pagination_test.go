package pagination_test

import (
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

func TestApplyDefaultsAndClamp(t *testing.T) {
	var p pagination.Params
	p.ApplyDefaultsAndClamp()
	if p.Limit != pagination.DefaultLimit {
		t.Fatalf("default limit: got %d", p.Limit)
	}
	p.Limit = 9999
	p.ApplyDefaultsAndClamp()
	if p.Limit != pagination.MaxLimit {
		t.Fatalf("max clamp: got %d", p.Limit)
	}
}
