package pii

import "github.com/basaltdbhq/basaltdb/internal/core/piistore"

// Sampled reports whether basalt classify samples a field of this kind:
// text-like, integer and numeric.
func Sampled(k piistore.Kind) bool {
	switch k {
	case piistore.KindText, piistore.KindInt, piistore.KindNumeric:
		return true
	case piistore.KindOther, piistore.KindDate, piistore.KindBool:
	}
	return false
}
