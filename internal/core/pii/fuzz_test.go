package pii_test

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

var fuzzSeeds = []string{
	"Customer Alice Tamm (fixture.alice.tamm@gmail.com, +44 7700 900123)",
	"Jose\u0301 Pe\u0301rez, Pa\u0308rnu mnt 99, Tallinn",
	"İstanbul ΟΔΥΣΣΕΥΣ Straße Ali\u200bce Tamm",
	"pii1_AAAAAAAAAAAA@redacted.invalid +44 pii1_BBBBBBBBBBBB Person CCCCCCCCCCCC",
	"+447700900456 (202) 555-0143 0812-3456-7890",
	"+447700900456x123",
	"a@b.cc+447700900456",
	"\u07e4\u0740\u0600\u05a4",
	"+447700900456+447700900457",
	"+447700900456_",
	"+44 7700 900456ext2",
	"\uff21\uff4c\uff45\uff58\uff41\uff4e\uff44\uff52\uff41 \uff2a\uff4f\uff4e\uff45\uff53 \uff41\uff4c\uff49\uff43\uff45@example.com \uff0b\uff14\uff14\uff17\uff17\uff10\uff10\uff19\uff10\uff10\uff14\uff15\uff16",
	"alice@ex\u00e4mple.ee xpii1_ABCDEFGHIJKL@corp.com",
	"bob.o'connor@corp.ee john&jane@x.ee zed{q}@other.com \"alice\"@corp.ee zed.q@other\u3002com",
	"email='bob@corp.ee' |x@y.zz| ?e=a@b.cc",
	"+1  202 555 0143\n+44\u20117700\u2212900123 +1 202/555/0143 0044 20 7946 0958",
	"0012 (202) 555-0143 2026-11-12 00112233-4455",
	"\"bob\".\"smith\"@corp.ee bob.\"a\\\nb\"@x.ee /users/bob@corp.ee/edit d'o'b@x.ee a‐b@corp.ee",
	"delta +30 2026/11/12 +12/11/2026 7\t+12\t3456\t7890 +100\n250\n3000\n42 +49 89/1234 5678",
	"card 4111 1111 1111 1111, 5555-5555-5555-4444 3782 822463 10005 +4111111111111111 +1 4111 1111 1111 1111 22",
	"iban EE38 2200 2210 2014 5685 DE89 3704 0044 0532 0130 00 gb82west12345698765432 order 1234567812345670",
	"the total price is 10 EUR; please park the car near the green door, Alice Tamm",
	"Rose said hi. Mr. Rose and mrs rose; ask Rose. \"Rose\" pii1_AAAAAAAAAAAA Rose (Rose)",
	"iban de89-3704-0044-0532-0130-00 EE38  2200  2210  2014  5685 x+4111111111111111",
	"",
}

// Normalizing twice changes nothing, for every type.
func FuzzNormalizeIsIdempotent(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			t.Skip()
		}
		for _, region := range []string{"", "ID", "US"} {
			for _, typ := range pii.TokenTypes() {
				once := pii.Normalize(typ, s, region)
				require.Equal(t, once, pii.Normalize(typ, once, region), "%s %s %q", typ, region, s)
			}
		}
	})
}
