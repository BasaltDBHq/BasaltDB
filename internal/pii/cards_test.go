package pii_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

func TestLuhnValid(t *testing.T) {
	cases := []struct {
		digits string
		want   bool
	}{
		{"4111111111111111", true},
		{"79927398713", true},
		{"0", false},
		{"", false},
		{"4111111111111112", false},
		{"79927398710", false},
		{"4111 1111 1111 1111", false}, // compact values only
		{"411111111111111a", false},
	}
	for _, c := range cases {
		require.Equal(t, c.want, pii.LuhnValid(c.digits), c.digits)
	}
}

func TestValidCardNumber(t *testing.T) {
	cases := []struct {
		name, digits string
		want         bool
	}{
		{"Visa", "4111111111111111", true},
		{"Visa 13", "4222222222222", true},
		{"Visa 19", "4111111111111111110", true},
		{"Mastercard", "5555555555554444", true},
		{"Mastercard 2-series", "2223003122003222", true},
		{"American Express", "378282246310005", true},
		{"Diners Club", "30569309025904", true},
		{"Discover", "6011111111111117", true},
		{"JCB", "3530111333300000", true},
		{"UnionPay", "6200000000000005", true},
		{"Luhn fails", "4111111111111112", false},
		{"no issuer: an order id", "1234567812345670", false},
		{"no issuer: a millisecond timestamp", "1731400000005", false},
		{"no issuer: nines", "9999999999999995", false},
		{"Visa of 15 digits", "411111111111116", false},
		{"Mastercard of 14 digits", "55555555555546", false},
		{"American Express of 14 digits", "37828224631003", false},
		{"too short", "411111111116", false},
		{"too long", "41111111111111111115", false},
		{"not digits", "4111-1111-1111-1111", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, pii.ValidCardNumber(c.digits))
		})
	}
}

func TestValidIBAN(t *testing.T) {
	cases := []struct {
		iban string
		want bool
	}{
		{"EE382200221020145685", true},
		{"GB82WEST12345698765432", true},
		{"DE89370400440532013000", true},
		{"NL91ABNA0417164300", true},
		{"FR1420041010050500013M02606", true},
		{"NO9386011117947", true},
		{"BE68539007547034", true},
		{"ee382200221020145685", true}, // any case
		{"EE382200221020145686", false},
		{"EE38220022102014568", false},   // one short of Estonia's 20
		{"EE3822002210201456850", false}, // one over
		{"XX382200221020145685", false},  // no such country
		{"EEAB2200221020145685", false},  // check digits are digits
		{"EE38 2200 2210 2014 5685", false},
		{"GB82WEST1234569876543!", false},
		{"EE", false},
		{"", false},
	}
	for _, c := range cases {
		require.Equal(t, c.want, pii.ValidIBAN(c.iban), c.iban)
	}
	require.Equal(t, 20, pii.IBANLength("ee"))
	require.Zero(t, pii.IBANLength("XX"))
}

// Each card or IBAN is found whole and tokenized as one CARD or IBAN value:
// the tokenizer never shows a digit of it, and a second pass changes nothing.
func TestCardsAndIBANsAreTokenized(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := patternTokenizer(t)
	cases := []struct{ name, in, value string }{
		{"card in groups of four (QA N12)", "card 4111 1111 1111 1111 ok", "4111 1111 1111 1111"},
		{"card with dashes", "card 4111-1111-1111-1111 ok", "4111-1111-1111-1111"},
		{"card with Unicode dashes", "card 4111‑1111‑1111‑1111 ok", "4111‑1111‑1111‑1111"},
		{"card without separators", "card 4111111111111111.", "4111111111111111"},
		{"card in full-width digits", "card ４１１１１１１１１１１１１１１１ ok", "４１１１１１１１１１１１１１１１"},
		{"Visa of 13", "card 4222222222222 ok", "4222222222222"},
		{"Visa of 19 in groups", "card 4111 1111 1111 1111 110 ok", "4111 1111 1111 1111 110"},
		{"American Express 4-6-5", "amex 3782 822463 10005 ok", "3782 822463 10005"},
		{"Diners Club 4-6-4", "diners 3056 930902 5904 ok", "3056 930902 5904"},
		{"Mastercard in JSON", `{"pan":"5555555555554444"}`, "5555555555554444"},
		{"card then more digits", "card 4111 1111 1111 1111 22", "4111 1111 1111 1111"},
		{"card after a longer group run", "ref 1234 4111 1111 1111 1111", "4111 1111 1111 1111"},
		{"card after a country code", "+1 4111 1111 1111 1111", "4111 1111 1111 1111"},
		{"card of 16 digits after a plus, the plus taken in", "card +4111111111111111 ok", "+4111111111111111"},
		{"IBAN in groups (QA N13)", "iban EE38 2200 2210 2014 5685", "EE38 2200 2210 2014 5685"},
		{"IBAN compact", "iban EE382200221020145685.", "EE382200221020145685"},
		{"IBAN in lower case", "iban ee38 2200 2210 2014 5685 ok", "ee38 2200 2210 2014 5685"},
		{"IBAN with letters in its BBAN", "to GB82 WEST 1234 5698 7654 32 now", "GB82 WEST 1234 5698 7654 32"},
		{"IBAN with a group like a phone", "iban DE89 3704 0044 0532 0130 00 ok", "DE89 3704 0044 0532 0130 00"},
		{"IBAN of an odd length", "iban FR14 2004 1010 0505 0001 3M02 606 ok", "FR14 2004 1010 0505 0001 3M02 606"},
		{"shortest IBAN", "konto NO93 8601 1117 947", "NO93 8601 1117 947"},
		{"IBAN then more groups", "iban EE38 2200 2210 2014 5685 99", "EE38 2200 2210 2014 5685"},
		{"IBAN with dashes", "iban DE89-3704-0044-0532-0130-00 ok", "DE89-3704-0044-0532-0130-00"},
		{"IBAN with double spaces", "iban DE89  3704  0044  0532  0130  00 ok", "DE89  3704  0044  0532  0130  00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, 1, finalScan(t, tz, c.in))
			out, reps := tokenize(t, tz, c.in)
			require.Len(t, reps, 1)
			require.Equal(t, c.value, c.in[reps[0].Start:reps[0].End], "the whole value")
			typ := pii.EntityCard
			if strings.ContainsAny(strings.ToUpper(c.value), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				typ = pii.EntityIBAN
			}
			require.Equal(t, mustToken(t, k, typ, c.value, ""), reps[0].Token)
			require.NotContains(t, out, c.value)
			require.Zero(t, finalScan(t, tz, out))
			again, more := tokenize(t, tz, out)
			require.Empty(t, more)
			require.Equal(t, out, again)
		})
	}
}

// Numbers that look like cards or IBANs but are not stay as they are: the
// checksum, the issuer prefix, the length and the word boundary all count.
func TestCardAndIBANLookalikesAreLeftAlone(t *testing.T) {
	tz := patternTokenizer(t)
	for _, in := range []string{
		"order 1234567812345670 shipped",    // Luhn-valid, no issuer
		"order 1234 5678 1234 5670 shipped", // the same in groups
		"at 1731400000005 ms",               // a timestamp, Luhn-valid
		"id 9999999999999995",               // Luhn-valid, no issuer
		"card 4111 1111 1111 1112",          // Luhn fails
		"card 4111111111111112",             // Luhn fails
		"id 41111111111111111115",           // 20 digits: an id
		"sha a4111111111111111f",            // hex
		"x4111111111111111",                 // glued to a letter
		"4111111111111111x",                 // glued to a letter
		"card 4111 1111-1111 1111",          // mixed separators
		"card 4111  1111  1111  1111",       // two spaces
		"card 41 11 1111 1111 1111",         // not a card layout
		"visa 411111111111116",              // Visa does not issue 15 digits
		"iban EE38 2200 2210 2014 5686",     // mod-97 fails
		"iban XX38 2200 2210 2014 5685",     // no such country
		"iban EE38 2200 2210 2014 568",      // too short
		"iban EE38 2200 2210 2014 56851",    // glued digit
		"iban EE382200221020145685X",        // glued letter
		"iban xEE382200221020145685",        // glued letter
		"iban EE3 82200 2210 2014 5685",
		"iban EE38     2200 2210 2014 5685", // five spaces
		"iban EE38--2200-2210-2014-5685",    // two dashes
		// a space inside a group
		"version 2026.11.12 build 20261112093000123", // dates and build numbers
		"uuid 550e8400-e29b-41d4-a716-446655440000",  // a UUID
		"price 1,234,567,890,123.45 EUR",             // an amount
	} {
		require.Zero(t, finalScan(t, tz, in), "%q", in)
	}
}

// A '+' number of at most 15 digits is a phone's, even when it would pass as a
// card, so a phone keeps its phone token.
func TestAPlusNumberIsAPhoneNotACard(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := patternTokenizer(t)
	in := "Nr. +4915112345678"
	_, reps := tokenize(t, tz, in)
	require.Len(t, reps, 1)
	require.Equal(t, mustToken(t, k, pii.EntityPhone, "+4915112345678", ""), reps[0].Token)
}

func TestIsCommonWord(t *testing.T) {
	for _, w := range []string{"price", "Park", "GREEN", "brown", "white", "young", "hall", "wood", "rose", "may", "june", "will"} {
		require.True(t, pii.IsCommonWord(w), w)
	}
	for _, w := range []string{"Tamm", "Alice", "Lepik", "Rebane", "Kask", "smith", "price park", ""} {
		require.False(t, pii.IsCommonWord(w), w)
	}
}

// QA N05 to N07: a single dictionary name that is also a common word is left
// alone in ordinary sentences; as part of a full name it is still tokenized,
// and a single name that is no common word is tokenized alone.
func TestSingleCommonWordsAreMatchedOnlyInFullNames(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	for _, v := range []string{"Price", "Park", "Green", "Brown", "May", "Tamm", "Alice Price", "Jaan Park"} {
		d.add(k, pii.EntityPersonName, v)
	}
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(k, d, ""))...)
	untouched := []string{
		"the total price is 10 EUR",
		"please park the car near the green door",
		"a brown fox",
		"We may ship in June",
		"Price: 10 EUR",
	}
	for _, in := range untouched {
		out, reps := tokenize(t, tz, in)
		require.Empty(t, reps, in)
		require.Equal(t, in, out)
	}
	cases := []struct{ in, value string }{
		{"ask Alice Price today", "Alice Price"},
		{"ask Jaan Park today", "Jaan Park"},
		{"ask Tamm today", "Tamm"},
	}
	for _, c := range cases {
		out, reps := tokenize(t, tz, c.in)
		require.Len(t, reps, 1, c.in)
		require.Equal(t, c.value, c.in[reps[0].Start:reps[0].End])
		require.NotContains(t, out, c.value)
		require.Zero(t, finalScan(t, tz, out))
	}
}

// A card or an IBAN gets one token however it is spaced (PT-9), and a card or
// IBAN stored compact in an OTHER column gets the token of its spaced form.
func TestCardsAndIBANsGetOneTokenHoweverSpaced(t *testing.T) {
	k := newKeys(t, testMaster)
	tz := patternTokenizer(t)
	groups := [][]string{
		{"4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111", "+4111111111111111", "4111‑1111‑1111‑1111"},
		{"EE38 2200 2210 2014 5685", "EE382200221020145685", "ee38-2200-2210-2014-5685", "EE38  2200  2210  2014  5685"},
	}
	for _, g := range groups {
		var first pii.Token
		for i, v := range g {
			_, reps := tokenize(t, tz, "value "+v+" end")
			require.Len(t, reps, 1, v)
			if i == 0 {
				first = reps[0].Token
				continue
			}
			require.Equal(t, first, reps[0].Token, v)
		}
		stored := mustToken(t, k, pii.EntityOther, strings.NewReplacer(" ", "", "-", "", "‑", "", "+", "").Replace(g[1]), "")
		require.Equal(t, first, stored, "a compact OTHER value is tokenized as the pattern tokenizes it")
	}
	require.Equal(t, "4111111111111111", pii.Normalize(pii.EntityCard, "4111 1111-1111 1111", ""))
	require.Equal(t, "EE382200221020145685", pii.Normalize(pii.EntityIBAN, "ee38 2200-2210 2014 5685", ""))
	other := mustToken(t, k, pii.EntityOther, "order 1234", "")
	require.Equal(t, pii.EntityOther, other.Type, "an OTHER value that is no card or IBAN keeps its type")
}

// A compact IBAN stored in the dictionary (an OTHER column) and the same IBAN
// written spaced in text get one token, so the engine and the proxy agree.
func TestAStoredCompactIBANMatchesTheSpacedForm(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityOther, "EE382200221020145685")
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(k, d, ""))...)
	stored := mustToken(t, k, pii.EntityOther, "EE382200221020145685", "")
	for _, in := range []string{"pay EE38 2200 2210 2014 5685 now", "pay EE382200221020145685 now", "pay EE38-2200-2210-2014-5685 now"} {
		_, reps := tokenize(t, tz, in)
		require.Len(t, reps, 1, in)
		require.Equal(t, stored, reps[0].Token, in)
	}
}

// Detection is deterministic (owner decision DD-1): a stored one-word name
// that is also a common word is never tokenized alone in free text, whatever
// stands around it, while a stored full name is, and so is a stored name
// that is no common word.
func TestCommonWordNamesAreNeverGuessed(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	for _, v := range []string{"Price", "Brown", "Hope", "Green", "Rose", "Iman Tumorang", "Tumorang"} {
		d.add(k, pii.EntityPersonName, v)
	}
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(k, d, ""))...)
	cases := []struct {
		in    string
		names []string
	}{
		{"note: Rose called about the invoice", nil},
		{"note: Iman Tumorang called about the invoice", []string{"Iman Tumorang"}},
		{"note: Tumorang, Iman called", []string{"Tumorang, Iman"}},
		{"ask Tumorang about it", []string{"Tumorang"}},
		{"Price called", nil},
		{"the price went up", nil},
		{"Mr. Brown called", nil},
		{"Dr Hope is in", nil},
		{"Bapak Brown datang", nil},
		{"Dear Rose,", nil},
		{"ask Hope about it", nil},
		{"I met Green and Brown", nil},
		{"Hope Green", nil},
		{`{"first_name":"Hope"}`, nil},
		{"Total Price", nil},
		{"| Price | Qty |", nil},
		{"## Price", nil},
	}
	for _, c := range cases {
		out, reps := tokenize(t, tz, c.in)
		require.Len(t, reps, len(c.names), "%q", c.in)
		for i, n := range c.names {
			require.Equal(t, n, c.in[reps[i].Start:reps[i].End], "%q", c.in)
		}
		again, more := tokenize(t, tz, out)
		require.Empty(t, more, "%q", c.in)
		require.Equal(t, out, again, "%q", c.in)
	}
}

// A common-word value is still masked in its own classified column: the
// column's value is tokenized as a whole, without detection, and is in the
// dictionary.
func TestACommonWordColumnValueIsStillMasked(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPersonName, "Rose")
	tok, err := k.MakeToken(pii.EntityPersonName, "Rose", "")
	require.NoError(t, err)
	require.NotContains(t, tok.Surface(), "Rose")
	require.True(t, d.Contains(pii.EntityPersonName, k.TypedHash(pii.EntityPersonName, "Rose", "")))
	require.True(t, pii.IsCommonWord("Rose"))
}
