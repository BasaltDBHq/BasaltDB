package pii_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
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

// A card or an IBAN gets one token however it is spaced (PT-9), and one
// stored in an OTHER column gets the token of its card or IBAN form.
func TestCardsAndIBANsGetOneTokenHoweverSpaced(t *testing.T) {
	t.Parallel()
	k := newKeys(t, testMaster)
	for typ, g := range map[pii.EntityType][]string{
		pii.EntityCard: {"4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111", "4111‑1111‑1111‑1111"},
		pii.EntityIBAN: {"EE38 2200 2210 2014 5685", "EE382200221020145685", "ee38-2200-2210-2014-5685", "EE38  2200  2210  2014  5685"},
	} {
		first := mustToken(t, k, typ, g[0], "")
		for _, v := range g {
			require.Equal(t, first, mustToken(t, k, typ, v, ""), v)
			stored := mustToken(t, k, pii.EntityOther, v, "")
			require.Equal(t, typ, stored.Type, "%s: an OTHER value that is a %s is tokenized as one", v, typ)
			require.Equal(t, first, stored, v)
		}
	}
	require.Equal(t, "4111111111111111", pii.Normalize(pii.EntityCard, "4111 1111-1111 1111", ""))
	require.Equal(t, "EE382200221020145685", pii.Normalize(pii.EntityIBAN, "ee38 2200-2210 2014 5685", ""))
	other := mustToken(t, k, pii.EntityOther, "order 1234", "")
	require.Equal(t, pii.EntityOther, other.Type, "an OTHER value that is no card or IBAN keeps its type")
}

// A card written in the decimal digits of any script normalizes to its
// ASCII digits.
func TestACardInAnyScriptsDigitsNormalizesToASCII(t *testing.T) {
	t.Parallel()
	n := 0
	for z := rune(0); z <= unicode.MaxRune; z++ {
		if !unicode.Is(unicode.Nd, z) || unicode.Is(unicode.Nd, z-1) {
			continue
		}
		n++
		in := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return z + (r - '0')
			}
			return r
		}, "4111 1111 1111 1111")
		require.Equal(t, "4111111111111111", pii.Normalize(pii.EntityCard, in, ""), "%U", z)
	}
	require.Greater(t, n, 60, "sanity: Unicode has dozens of digit blocks")
}
