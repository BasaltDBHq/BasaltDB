package pii

import (
	"strconv"
	"strings"
)

// The validators in this file are the one implementation of the card and IBAN
// checks: the pattern detectors (CardDetector, IBANDetector) use them on text,
// and internal/pii uses them on sampled column values (M5.1 plan,
// section 3). They take a compact value: no spaces or dashes.

// Card numbers are 13 to 19 digits (ISO/IEC 7812).
const (
	minCardDigits = 13
	maxCardDigits = 19
)

// luhnDoubleOver is what a doubled Luhn digit above 9 is reduced by (the sum of
// its two digits: 2d - 9).
const luhnDoubleOver = 9

// LuhnValid reports whether digits (ASCII digits only, at least two) pass the
// Luhn check.
func LuhnValid(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if !isASCIIDigit(c) {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > luhnDoubleOver {
				d -= luhnDoubleOver
			}
		}
		sum += d
		double = !double
	}
	return sum%decimalDigits == 0
}

// cardIssuer is a range of issuer identification numbers: the first
// len(lo) digits of a card number between lo and hi, and the lengths cards of
// that range have (bit n set for n digits).
type cardIssuer struct {
	lo, hi  string
	lengths uint32
}

// cardLengthsFrom is the bit set of the lengths from lo to maxCardDigits.
func cardLengthsFrom(lo int) uint32 {
	var m uint32
	for n := lo; n <= maxCardDigits; n++ {
		m |= 1 << n
	}
	return m
}

// cardLength is the bit set of single lengths.
func cardLength(ns ...int) uint32 {
	var m uint32
	for _, n := range ns {
		m |= 1 << n
	}
	return m
}

// Card lengths by network (ISO/IEC 7812 and the networks' published ranges).
const (
	visaShort  = 13
	cardStd    = 16
	verveMid   = 18
	visaLong   = 19
	amexLen    = 15
	dinersMin  = 14
	maestroMin = 13
)

// cardIssuers are the issuer ranges a card number must start with. A number
// with no known issuer (order ids, timestamps, which start with 1) is no card.
var cardIssuers = []cardIssuer{
	{"4", "4", cardLength(visaShort, cardStd, visaLong)},          // Visa
	{"51", "55", cardLength(cardStd)},                             // Mastercard
	{"2221", "2720", cardLength(cardStd)},                         // Mastercard 2-series
	{"34", "34", cardLength(amexLen)},                             // American Express
	{"37", "37", cardLength(amexLen)},                             // American Express
	{"300", "305", cardLengthsFrom(dinersMin)},                    // Diners Club
	{"36", "36", cardLengthsFrom(dinersMin)},                      // Diners Club
	{"38", "39", cardLengthsFrom(cardStd)},                        // Diners Club
	{"3528", "3589", cardLengthsFrom(cardStd)},                    // JCB
	{"6011", "6011", cardLengthsFrom(cardStd)},                    // Discover
	{"644", "649", cardLengthsFrom(cardStd)},                      // Discover
	{"65", "65", cardLengthsFrom(cardStd)},                        // Discover, RuPay
	{"62", "62", cardLengthsFrom(cardStd)},                        // UnionPay
	{"2200", "2204", cardLengthsFrom(cardStd)},                    // Mir
	{"60", "60", cardLength(cardStd)},                             // RuPay
	{"81", "82", cardLength(cardStd)},                             // RuPay
	{"508", "508", cardLength(cardStd)},                           // RuPay
	{"9792", "9792", cardLength(cardStd)},                         // Troy
	{"5018", "5018", cardLengthsFrom(maestroMin)},                 // Maestro
	{"5020", "5020", cardLengthsFrom(maestroMin)},                 // Maestro
	{"5038", "5038", cardLengthsFrom(maestroMin)},                 // Maestro
	{"5893", "5893", cardLengthsFrom(maestroMin)},                 // Maestro
	{"6304", "6304", cardLengthsFrom(maestroMin)},                 // Maestro
	{"6759", "6759", cardLengthsFrom(maestroMin)},                 // Maestro
	{"6761", "6763", cardLengthsFrom(maestroMin)},                 // Maestro
	{"506099", "506198", cardLength(cardStd, verveMid, visaLong)}, // Verve
	{"650002", "650027", cardLength(cardStd, verveMid, visaLong)}, // Verve
}

// ValidCardNumber reports whether digits (ASCII digits only) is a payment card
// number: 13 to 19 digits, a known issuer range with a length that range
// issues, and the Luhn check.
func ValidCardNumber(digits string) bool {
	if len(digits) < minCardDigits || len(digits) > maxCardDigits || !LuhnValid(digits) {
		return false
	}
	return knownIssuer(digits)
}

func knownIssuer(digits string) bool {
	for _, iss := range cardIssuers {
		p := digits[:len(iss.lo)]
		if p >= iss.lo && p <= iss.hi && iss.lengths&(1<<len(digits)) != 0 {
			return true
		}
	}
	return false
}

// ibanRegistry is the length of an IBAN by country (ISO 13616, the SWIFT IBAN
// registry), as country code and length. A country that is not here is no IBAN.
const ibanRegistry = `AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22
CY28 CZ24 DE22 DJ27 DK18 DO28 EE20 EG29 ES24 FI18 FK18 FO18 FR27 GB22 GE22 GI23
GL18 GR27 GT28 HN28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32
LI21 LT20 LU20 LV21 LY25 MC27 MD24 ME22 MK19 MN20 MR27 MT31 MU30 NI28 NL18 NO15
OM23 PK24 PL28 PS29 PT25 QA29 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 SK24 SM27
SO23 ST25 SV28 TL23 TN24 TR26 UA29 VA22 VG24 XK20 YE30`

// ibanLengths is ibanRegistry as a map.
var ibanLengths = parseIBANRegistry(ibanRegistry)

func parseIBANRegistry(reg string) map[string]int {
	out := make(map[string]int)
	for _, e := range strings.Fields(reg) {
		n, err := strconv.Atoi(e[ibanCountry:])
		if err != nil {
			panic("pii: bad IBAN registry entry " + e)
		}
		out[e[:ibanCountry]] = n
	}
	return out
}

// ibanHead is the country code and check digits that start an IBAN.
const ibanHead = 4

// ibanMod is the ISO 7064 MOD 97-10 modulus, and ibanRemainder what a valid
// IBAN leaves.
const (
	ibanMod       = 97
	ibanRemainder = 1
)

// ibanLetterBase is the value of 'A' in the mod-97 check (A=10 … Z=35).
const ibanLetterBase = 10

// IBANLength is the length of an IBAN of country (two letters, any case), or 0
// for a country with no IBAN.
func IBANLength(country string) int { return ibanLengths[strings.ToUpper(country)] }

// ValidIBAN reports whether s (compact, no spaces; any case) is an IBAN: a
// country with IBANs, its length, two check digits, letters and digits only,
// and the mod-97 check.
func ValidIBAN(s string) bool {
	if len(s) < ibanHead || len(s) != IBANLength(s[:2]) || !isASCIIDigit(s[2]) || !isASCIIDigit(s[3]) {
		return false
	}
	rem := 0
	for i := range len(s) {
		c := s[(i+ibanHead)%len(s)]
		switch {
		case isASCIIDigit(c):
			rem = (rem*decimalDigits + int(c-'0')) % ibanMod
		case isASCIILetter(c):
			v := int(asciiUpper(c)-'A') + ibanLetterBase
			rem = (rem*decimalDigits*decimalDigits + v) % ibanMod
		default:
			return false
		}
	}
	return rem == ibanRemainder
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func asciiUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func isASCIIAlnum(c byte) bool {
	return isASCIIDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
