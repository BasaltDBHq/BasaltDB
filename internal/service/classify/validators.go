package classify

import (
	"bufio"
	_ "embed"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

// The card and IBAN checks are internal/core/pii's (pii.ValidCardNumber,
// pii.ValidIBAN, pii.LuhnValid), shared with the tokenizer's patterns.

// compact drops spaces and dashes, as cards, IBANs and IMEIs are often
// written in groups.
func compact(v string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.TrimSpace(v))
}

func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validCard(v string) bool {
	c := compact(v)
	return allASCIIDigits(c) && pii.ValidCardNumber(c)
}

func validIBAN(v string) bool { return pii.ValidIBAN(compact(v)) }

// imeiDigits is the length of an IMEI with its Luhn check digit.
const imeiDigits = 15

func validIMEI(v string) bool {
	c := compact(v)
	return len(c) == imeiDigits && allASCIIDigits(c) && pii.LuhnValid(c)
}

// validEmail is net/mail's address syntax, the bare address only, with a
// domain that holds a dot.
func validEmail(v string) bool {
	v = strings.TrimSpace(v)
	a, err := mail.ParseAddress(v)
	if err != nil || a.Name != "" || a.Address != v {
		return false
	}
	at := strings.LastIndexByte(v, '@')
	domain := v[at+1:]
	return strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}

// Indonesian NIK (Nomor Induk Kependudukan): 16 digits, a region code
// (province, regency, district: 2 digits each), the date of birth as DDMMYY
// (day + 40 for women) and a 4-digit serial.
const (
	nikDigits       = 16
	nikRegionEnd    = 6
	nikDateEnd      = 12
	nikWomanDayAdd  = 40
	nikCenturyLate  = 1900
	nikCenturyEarly = 2000
)

// nikProvinces are the province codes a NIK can start with (Kemendagri).
var nikProvinces = map[string]bool{
	"11": true, "12": true, "13": true, "14": true, "15": true, "16": true, "17": true, "18": true,
	"19": true, "21": true, "31": true, "32": true, "33": true, "34": true, "35": true, "36": true,
	"51": true, "52": true, "53": true, "61": true, "62": true, "63": true, "64": true, "65": true,
	"71": true, "72": true, "73": true, "74": true, "75": true, "76": true, "81": true, "82": true,
	"91": true, "92": true, "93": true, "94": true, "95": true, "96": true,
}

func validNIK(v string) bool {
	c := compact(v)
	if len(c) != nikDigits || !allASCIIDigits(c) || !nikProvinces[c[:2]] {
		return false
	}
	// Regency and district are never 00, and the serial never 0000.
	if c[2:4] == "00" || c[4:nikRegionEnd] == "00" || c[nikDateEnd:] == "0000" {
		return false
	}
	day, month, year := num(c[6:8]), num(c[8:10]), num(c[10:nikDateEnd])
	if day > nikWomanDayAdd {
		day -= nikWomanDayAdd
	}
	return validDate(nikCenturyLate+year, month, day) || validDate(nikCenturyEarly+year, month, day)
}

// decimalBase is the base of the digits num reads.
const decimalBase = 10

func num(s string) int {
	n := 0
	for i := range len(s) {
		n = n*decimalBase + int(s[i]-'0')
	}
	return n
}

func validDate(year, month, day int) bool {
	if month < 1 || month > 12 || day < 1 {
		return false
	}
	d := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	return d.Day() == day && int(d.Month()) == month
}

//go:embed firstnames.txt
var firstNamesText string

// firstNames is the embedded first-name list.
var firstNames = parseFirstNames(firstNamesText)

func parseFirstNames(text string) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
}

// startsWithFirstName reports whether the first word of v is a first name of
// the list, in any case.
func startsWithFirstName(v string) bool {
	fs := strings.Fields(v)
	if len(fs) == 0 {
		return false
	}
	w := strings.TrimFunc(strings.ToLower(fs[0]), func(r rune) bool { return !unicode.IsLetter(r) })
	return firstNames[w]
}

// codeLike reports whether v is a code: no lower-case letter and no space,
// only upper-case letters, digits and code punctuation (A-100, INV/2026/7).
func codeLike(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./:#", r):
		default:
			return false
		}
	}
	return true
}

// anyValidator reports whether v passes any validator, counting every
// phone-shaped run of digits (bare ones too) as a phone.
func anyValidator(v string) bool {
	if validCard(v) || validNIK(v) || validIBAN(v) || validEmail(v) || validIMEI(v) || startsWithFirstName(v) {
		return true
	}
	_, phone := shapePhone(v, true)
	return phone
}

// maxShortCode is the longest value shortCodes accepts.
const maxShortCode = 20

// shortCodes reports whether every value is a short code or flag (verified,
// true, A-100): no space, at most maxShortCode characters, and no validator
// passes.
func shortCodes(values []string) bool {
	for _, v := range values {
		if hasSpace(v) || runeLen(strings.TrimSpace(v)) > maxShortCode || anyValidator(v) {
			return false
		}
	}
	return true
}

func hasSpace(v string) bool { return strings.ContainsFunc(strings.TrimSpace(v), unicode.IsSpace) }

func runeLen(v string) int { return utf8.RuneCountInString(v) }
