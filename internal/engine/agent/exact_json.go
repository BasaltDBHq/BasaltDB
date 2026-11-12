package agent

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// decodeExact decodes JSON keeping every number as its json.Number text.
func decodeExact(raw []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

// sameJSON compares two values from decodeExact. Numbers are equal when
// their decimal values are (1e2 and 100.0 are, 9007199254740993 and
// 9007199254740992 are not).
func sameJSON(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		return ok && sameNumber(x, y)
	case []any:
		y, ok := b.([]any)
		return ok && sameArrays(x, y)
	case map[string]any:
		y, ok := b.(map[string]any)
		return ok && sameObjects(x, y)
	}
	return a == b // string, bool or nil
}

func sameArrays(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameJSON(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameObjects(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !sameJSON(v, w) {
			return false
		}
	}
	return true
}

// sameNumber compares two JSON numbers by exact decimal value. A number
// whose exponent is out of range compares by its text.
func sameNumber(a, b json.Number) bool {
	x, okA := decimalOf(string(a))
	y, okB := decimalOf(string(b))
	if !okA || !okB {
		return a == b
	}
	return x == y
}

// decimal is a JSON number as sign, significant digits (no leading or
// trailing zeros) and the power of ten of the last digit. Zero has no
// digits and no sign.
type decimal struct {
	negative bool
	digits   string
	exponent int64
}

// maxExponent bounds the exponents decimalOf adjusts, far past anything
// Postgres numeric holds, so the arithmetic cannot overflow.
const maxExponent = 1 << 40

func decimalOf(s string) (decimal, bool) {
	var d decimal
	s, d.negative = strings.CutPrefix(s, "-")
	mantissa, expText, hasExp := strings.Cut(strings.ToLower(s), "e")
	if hasExp {
		e, err := strconv.ParseInt(expText, 10, 64)
		if err != nil || e > maxExponent || e < -maxExponent {
			return decimal{}, false
		}
		d.exponent = e
	}
	whole, frac, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+frac, "0")
	d.exponent -= int64(len(frac))
	trimmed := strings.TrimRight(digits, "0")
	d.exponent += int64(len(digits) - len(trimmed))
	d.digits = trimmed
	if d.digits == "" {
		return decimal{}, true
	}
	return d, true
}
