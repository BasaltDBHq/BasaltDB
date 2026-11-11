package setupcode_test

import (
	"errors"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// FuzzDecode checks the decoder never panics, refuses only with one of its
// four refusals, and that whatever it accepts is valid and re-encodes to a
// code that decodes to the same payload.
func FuzzDecode(f *testing.F) {
	fx := loadFixtures(f)
	for _, v := range fx.Valid {
		f.Add(v.Code)
	}
	for _, v := range fx.Invalid {
		f.Add(v.Code)
	}
	f.Add("")
	f.Add("basalt-setup.")
	f.Add("basalt-setup.1.")
	f.Add("basalt-setup.1..")
	f.Fuzz(func(t *testing.T, code string) {
		p, err := setupcode.Decode(code)
		if err != nil {
			var e *setupcode.Error
			if !errors.As(err, &e) {
				t.Fatalf("not a *setupcode.Error: %v", err)
			}
			switch e.Refusal {
			case setupcode.RefusalNotASetupCode, setupcode.RefusalUnsupportedFormat, setupcode.RefusalDamaged, setupcode.RefusalInvalid:
			default:
				t.Fatalf("unexpected refusal %s", e.Refusal)
			}
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("decoded payload does not validate: %v", err)
		}
		again, err := setupcode.Encode(p)
		if errors.Is(err, setupcode.ErrCodeTooLong) {
			return
		}
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		q, err := setupcode.Decode(again)
		if err != nil {
			t.Fatalf("decode re-encoded: %v", err)
		}
		if p.Fingerprint() != q.Fingerprint() || p.SetupID != q.SetupID {
			t.Fatalf("re-encoded code decodes differently")
		}
	})
}

// FuzzDecodePayload fuzzes the JSON inside a code with a correct check, so
// the fuzzer reaches the payload rules instead of stopping at DAMAGED.
func FuzzDecodePayload(f *testing.F) {
	f.Add([]byte(`{"format":1}`))
	f.Add([]byte(`{"format":2}`))
	f.Add([]byte(`[]`))
	for _, v := range loadFixtures(f).Valid {
		f.Add([]byte(v.Payload))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		p, err := setupcode.Decode(rawCode(t, payload))
		if err != nil {
			var e *setupcode.Error
			if !errors.As(err, &e) {
				t.Fatalf("not a *setupcode.Error: %v", err)
			}
			if e.Refusal != setupcode.RefusalInvalid && e.Refusal != setupcode.RefusalUnsupportedFormat {
				t.Fatalf("unexpected refusal %s", e.Refusal)
			}
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("decoded payload does not validate: %v", err)
		}
	})
}
