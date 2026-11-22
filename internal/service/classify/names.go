package classify

import (
	"slices"
	"strings"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
)

// nameRule is one row of the name rules: any of its phrases (word sequences
// of the column name, lower case) suggests class and entity type.
type nameRule struct {
	class, entity string
	phrases       [][]string
	// kinds are the column kinds the rule applies to: an int column named
	// mail_count holds no email.
	kinds []kind
	// numericPhrases, when set, are the only phrases that also apply to
	// integer and numeric columns (a zip code may be stored as a number).
	numericPhrases [][]string
}

func words(s ...string) [][]string {
	out := make([][]string, 0, len(s))
	for _, p := range s {
		out = append(out, strings.Split(p, " "))
	}
	return out
}

// nameRules in the order they are tried: the most protective first, and
// addresses before person names so street_name is an address.
var nameRules = []nameRule{
	{
		class: guard.ClassSecret,
		phrases: words("password", "passwd", "secret", "token", "api key", "apikey", "hash", "ssn",
			"national id", "passport", "tax id", "card number", "cvv", "cvc", "nik", "pin", "otp", "passcode",
			"security code"),
		kinds: []kind{kindText, kindInt, kindNumeric, kindOther},
	},
	{
		class: guard.ClassIdentifier, entity: guard.EntityEmail,
		phrases: words("email", "e mail", "mail"),
		kinds:   []kind{kindText},
	},
	{
		class: guard.ClassIdentifier, entity: guard.EntityPhone,
		phrases: words("phone", "mobile", "tel", "msisdn", "telephone", "whatsapp"),
		kinds:   []kind{kindText, kindInt, kindNumeric},
	},
	{
		class: guard.ClassIdentifier, entity: guard.EntityOther,
		phrases: words("ip address", "mac address", "wallet address"),
		kinds:   []kind{kindText, kindOther},
	},
	{
		class: guard.ClassIdentifier, entity: guard.EntityAddress,
		phrases:        words("address", "street", "addr", "postcode", "zip", "zipcode", "postal code"),
		kinds:          []kind{kindText, kindInt, kindNumeric},
		numericPhrases: words("postcode", "zip", "zipcode", "postal code"),
	},
	{
		class: guard.ClassIdentifier, entity: guard.EntityOther,
		phrases: words("dob", "birth date", "date of birth", "birthdate", "birthday", "iban",
			"account number", "imei"),
		kinds: []kind{kindText, kindInt, kindNumeric, kindDate},
	},
	{
		class: guard.ClassIdentifier, entity: guard.EntityPersonName,
		phrases: words("name", "surname", "firstname", "lastname", "fullname", "givenname"),
		kinds:   []kind{kindText},
	},
	{
		class:   guard.ClassFreeText,
		phrases: words("notes", "note", "comment", "comments", "message", "messages", "body", "description", "bio"),
		kinds:   []kind{kindText},
	},
}

// nonPersonNames are the words that make X_name the name of a thing, not a
// person (table_name, product_name). Any other X_name is a person's.
var nonPersonNames = map[string]bool{
	"table": true, "column": true, "schema": true, "product": true, "file": true, "filename": true,
	"company": true, "org": true, "organization": true, "brand": true,
	"category": true, "project": true, "app": true, "application": true, "host": true, "domain": true,
	"event": true, "plan": true, "role": true, "team": true, "group": true, "item": true, "service": true,
	"country": true, "city": true, "state": true, "province": true, "region": true, "bucket": true,
	"key": true, "field": true, "index": true, "queue": true, "topic": true, "channel": true,
	"device": true, "package": true, "module": true, "function": true, "method": true, "class": true,
	"feature": true, "template": true, "page": true, "site": true, "store": true, "shop": true,
	"business": true, "merchant": true, "bank": true, "dataset": true, "database": true, "db": true,
	"server": true, "branch": true, "repo": true, "repository": true, "image": true, "metric": true,
	"tag": true, "type": true, "model": true, "vendor": true, "supplier": true, "course": true,
	"job": true, "task": true, "step": true, "status": true, "provider": true, "unit": true,
}

// qualifiers after a matched phrase make the column about the value, not the
// value itself: email_count, phone_verified, token_type, password_changed_at.
var qualifiers = map[string]bool{
	"count": true, "counts": true, "total": true, "status": true, "type": true, "kind": true,
	"verified": true, "confirmed": true, "enabled": true, "disabled": true, "sent": true,
	"template": true, "provider": true, "at": true, "flag": true, "length": true, "len": true,
	"size": true, "format": true, "expires": true, "expiry": true, "changed": true, "updated": true,
	"attempts": true, "algorithm": true, "version": true,
}

// nameHit is what the name rules say about a column.
type nameHit struct {
	class, entity string
	// word is the column name, for the reason.
	word string
	// qualified is a match followed by a qualifier (email_status,
	// phone_updated): the name is kept as a floor unless the sample shows
	// only short codes or flags.
	qualified bool
}

// match is how a rule matched a name.
type match int

const (
	noMatch match = iota
	qualifiedMatch
	fullMatch
)

// matchName applies the name rules to a column of kind k. A full match wins
// over a qualified one.
func matchName(name string, k kind) (nameHit, bool) {
	ws := splitName(name)
	var qualified *nameHit
	for _, r := range nameRules {
		if !slices.Contains(r.kinds, k) {
			continue
		}
		phrases := r.phrases
		if r.numericPhrases != nil && (k == kindInt || k == kindNumeric) {
			phrases = r.numericPhrases
		}
		switch ruleMatches(r, phrases, ws) {
		case fullMatch:
			return nameHit{class: r.class, entity: r.entity, word: name}, true
		case qualifiedMatch:
			if qualified == nil {
				qualified = &nameHit{class: r.class, entity: r.entity, word: name, qualified: true}
			}
		case noMatch:
		}
	}
	if qualified != nil {
		return *qualified, true
	}
	return nameHit{}, false
}

func ruleMatches(r nameRule, phrases [][]string, ws []string) match {
	best := noMatch
	for _, p := range phrases {
		for i := 0; i+len(p) <= len(ws); i++ {
			if !slices.Equal(ws[i:i+len(p)], p) {
				continue
			}
			if r.entity == guard.EntityPersonName && p[0] == "name" && i > 0 && nonPersonNames[ws[i-1]] {
				continue
			}
			end := i + len(p)
			if end < len(ws) && qualifiers[ws[end]] {
				best = qualifiedMatch
				continue
			}
			return fullMatch
		}
	}
	return best
}

// splitName lower-cases a column name and splits it on anything but letters
// and digits and on case changes: customerEmail and email_address both hold
// the word email.
func splitName(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
			continue
		case unicode.IsUpper(r) && len(cur) > 0 && (unicode.IsLower(cur[len(cur)-1]) ||
			(i+1 < len(rs) && unicode.IsLower(rs[i+1]))):
			flush()
		}
		cur = append(cur, r)
	}
	flush()
	return out
}
