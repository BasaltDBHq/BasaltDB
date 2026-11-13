package pii_test

import (
	"strings"
	"testing"
)

// wordDenseText is about size bytes of prose: short everyday words, with a
// known name, an email and a phone in every 40 words or so, the shape of a
// chat history the M5.3 proxy tokenizes again each turn.
func wordDenseText(size int) string {
	words := strings.Fields("the order was shipped on time and the customer asked about a refund for " +
		"two items in the last box we sent so please check the notes before you call back " +
		"with the new price list and update the ticket when it is done thanks")
	pii := []string{"Alice Tamm", "fixture.alice.tamm@gmail.com", "+44 7700 900123", "Rose Lepik", "+1 202 555 0143"}
	var b strings.Builder
	for i := 0; b.Len() < size; i++ {
		if i%40 == 39 {
			b.WriteString(pii[(i/40)%len(pii)])
		} else {
			b.WriteString(words[i%len(words)])
		}
		if i%12 == 11 {
			b.WriteString(".\n")
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// BenchmarkTokenizeWordDense measures the tokenizer with the pattern
// detectors and the fixture dictionary on word-dense text; -benchmem and the
// MB/s column give the rate to hold the budget to (M5.1 plan, Known limits, "Throughput").
func BenchmarkTokenizeWordDense(b *testing.B) {
	for _, size := range []struct {
		name  string
		bytes int
	}{{"4KB", 4 << 10}, {"64KB", 64 << 10}, {"1MB", 1 << 20}} {
		b.Run(size.name, func(b *testing.B) {
			tz := newTokenizer(b)
			text := wordDenseText(size.bytes)
			b.SetBytes(int64(len(text)))
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := tz.Tokenize(text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
