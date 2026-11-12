package classify

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

// Phone numbers are 6 to 15 digits (E.164 allows at most 15).
const (
	minPhoneDigits = 6
	maxPhoneDigits = 15
)

// Region inference first scores every region on a few local numbers, then
// counts the best few on the whole sample.
const (
	regionProbe      = 64
	regionFinalists  = 8
	phoneSeparators  = " -.()/"
	internationalOut = "00"
)

// phoneValue is a sampled value in the form libphonenumber parses: a leading
// 00 written as +, separators dropped.
type phoneValue struct {
	text          string
	international bool
}

// phoneShape returns the value as a phone candidate. bare allows a run of
// digits with no +, no leading 0 and no separator (an integer column). Such
// a run is read as international first when it is a valid number with a
// + before it (6281234567801 is +62, not a German local number).
func phoneShape(v string, bare bool) (phoneValue, bool) {
	pv, ok := shapePhone(v, bare)
	if !ok || pv.international || !bare || strings.HasPrefix(pv.text, "0") {
		return pv, ok
	}
	if intl := (phoneValue{text: "+" + pv.text, international: true}); validIn(intl, "") {
		return intl, true
	}
	return pv, true
}

// bareDigits reports whether v is a run of digits with no +, no leading 0
// and no separator: a phone only by its digits.
func bareDigits(v string) bool {
	v = strings.TrimSpace(v)
	return allASCIIDigits(v) && !strings.HasPrefix(v, "0")
}

func shapePhone(v string, bare bool) (phoneValue, bool) {
	v = strings.TrimSpace(v)
	separated := strings.ContainsAny(v, phoneSeparators)
	s := strings.Map(func(r rune) rune {
		if strings.ContainsRune(phoneSeparators, r) {
			return -1
		}
		return r
	}, v)
	international := strings.HasPrefix(s, "+")
	if strings.HasPrefix(s, internationalOut) {
		s, international = "+"+s[len(internationalOut):], true
	}
	digits := strings.TrimPrefix(s, "+")
	if !allASCIIDigits(digits) || len(digits) < minPhoneDigits || len(digits) > maxPhoneDigits {
		return phoneValue{}, false
	}
	if !international && !separated && !strings.HasPrefix(digits, "0") && !bare {
		return phoneValue{}, false
	}
	return phoneValue{text: s, international: international}, true
}

func validIn(v phoneValue, region string) bool {
	if v.international {
		region = ""
	}
	n, err := phonenumbers.Parse(v.text, region)
	return err == nil && phonenumbers.IsValidNumber(n)
}

// callingCode is the country calling code of a valid international number,
// 0 otherwise.
func callingCode(v phoneValue) int32 {
	if !v.international {
		return 0
	}
	n, err := phonenumbers.Parse(v.text, "")
	if err != nil || !phonenumbers.IsValidNumber(n) {
		return 0
	}
	return n.GetCountryCode()
}

// CallingCodes counts the +cc prefixes of valid international numbers in
// values, for weighting region inference across the database.
func CallingCodes(values []string, into map[int32]int) {
	for _, v := range values {
		pv, ok := phoneShape(v, false)
		if !ok {
			continue
		}
		if cc := callingCode(pv); cc != 0 {
			into[cc]++
		}
	}
}

// regionResult is the region a column's numbers parse as and how many of
// the sampled values are valid numbers there.
type regionResult struct {
	region string
	valid  int
}

// inferRegion finds the region where most of a column's phone candidates
// are valid numbers. International numbers are valid whatever the region;
// local ones decide it. Ties go to the region whose calling code the
// database holds most often (db, the +cc counts), then to the main region
// of a calling code, then by name. fixed, when set, is the region to use.
// With no local number the region is the main one of the commonest +cc in
// the column, or none.
func inferRegion(values []string, bare bool, fixed string, db map[int32]int) regionResult {
	var intl, local []phoneValue
	for _, v := range values {
		pv, ok := phoneShape(v, bare)
		switch {
		case !ok:
		case pv.international:
			intl = append(intl, pv)
		default:
			local = append(local, pv)
		}
	}
	intlValid := 0
	ccs := map[int32]int{}
	for _, v := range intl {
		if cc := callingCode(v); cc != 0 {
			intlValid++
			ccs[cc]++
		}
	}
	if fixed != "" {
		return regionResult{region: fixed, valid: intlValid + countValid(local, fixed)}
	}
	best := bestRegion(local, db)
	if best.valid == 0 {
		return regionResult{region: commonestRegion(ccs, db), valid: intlValid}
	}
	best.valid += intlValid
	return best
}

func countValid(vs []phoneValue, region string) int {
	n := 0
	for _, v := range vs {
		if validIn(v, region) {
			n++
		}
	}
	return n
}

func bestRegion(local []phoneValue, db map[int32]int) regionResult {
	if len(local) == 0 {
		return regionResult{}
	}
	regions := slices.Sorted(maps.Keys(phonenumbers.GetSupportedRegions()))
	probe := local[:min(regionProbe, len(local))]
	scored := make([]regionResult, 0, len(regions))
	for _, r := range regions {
		if n := countValid(probe, r); n > 0 {
			scored = append(scored, regionResult{region: r, valid: n})
		}
	}
	rank := func(a, b regionResult) int {
		return cmp.Or(
			cmp.Compare(b.valid, a.valid),
			cmp.Compare(db[regionCode(b.region)], db[regionCode(a.region)]),
			cmp.Compare(mainRegion(b.region), mainRegion(a.region)),
			cmp.Compare(a.region, b.region),
		)
	}
	slices.SortFunc(scored, rank)
	scored = scored[:min(regionFinalists, len(scored))]
	if len(probe) < len(local) {
		for i := range scored {
			scored[i].valid = countValid(local, scored[i].region)
		}
		slices.SortFunc(scored, rank)
	}
	if len(scored) == 0 {
		return regionResult{}
	}
	return scored[0]
}

func regionCode(region string) int32 { return int32(phonenumbers.GetCountryCodeForRegion(region)) }

// mainRegion is 1 for the main region of its calling code (US for +1).
func mainRegion(region string) int {
	if phonenumbers.GetRegionCodeForCountryCode(int(regionCode(region))) == region {
		return 1
	}
	return 0
}

// commonestRegion is the main region of the calling code seen most often in
// ccs, ties broken by the database counts, then the lower code.
func commonestRegion(ccs map[int32]int, db map[int32]int) string {
	if len(ccs) == 0 {
		return ""
	}
	codes := slices.SortedFunc(maps.Keys(ccs), func(a, b int32) int {
		return cmp.Or(cmp.Compare(ccs[b], ccs[a]), cmp.Compare(db[b], db[a]), cmp.Compare(a, b))
	})
	r := phonenumbers.GetRegionCodeForCountryCode(int(codes[0]))
	if r == "ZZ" || r == "001" {
		return ""
	}
	return r
}

// ValidRegion reports whether region (upper case) is an ISO 3166-1 alpha-2
// region libphonenumber has numbers for.
func ValidRegion(region string) bool {
	_, ok := phonenumbers.GetSupportedRegions()[region]
	return ok
}
