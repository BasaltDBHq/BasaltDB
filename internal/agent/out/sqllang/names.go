package sqllang

import (
	"errors"
	"strings"
)

// ParseName reads schema.table as Postgres prints it (parseResource).
func (Language) ParseName(s string) (namespace, name string, err error) {
	return parseResource(s)
}

// PrintName is schema.name as Postgres prints it (quote_ident).
func (Language) PrintName(namespace, name string) string { return printedName(namespace, name) }

// PrintName is schema.name as Postgres prints it (quote_ident), for the
// store wiring that renders a foreign key's other table.
func PrintName(schema, name string) string { return printedName(schema, name) }

// parseResource reads schema.table as Postgres prints it: each part bare
// (folded to lower case, as Postgres folds it) or double-quoted, with ""
// for a quote inside.
func parseResource(s string) (schema, name string, err error) {
	parts := make([]string, 0, 2)
	rest := s
	for {
		part, tail, err := parseIdent(rest)
		if err != nil {
			return "", "", err
		}
		parts = append(parts, part)
		if tail == "" {
			break
		}
		if tail[0] != '.' {
			return "", "", errors.New("must be schema.table")
		}
		rest = tail[1:]
	}
	if len(parts) != 2 {
		return "", "", errors.New("must be schema.table, with the schema")
	}
	return parts[0], parts[1], nil
}

// parseIdent reads one identifier from the front of s: a quoted one as
// written, an unquoted one folded as Postgres folds it (foldASCII).
func parseIdent(s string) (ident, rest string, err error) {
	if strings.HasPrefix(s, `"`) {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] != '"' {
				b.WriteByte(s[i])
				continue
			}
			if i+1 < len(s) && s[i+1] == '"' {
				b.WriteByte('"')
				i++
				continue
			}
			if b.Len() == 0 {
				return "", "", errors.New("has an empty quoted name")
			}
			return b.String(), s[i+1:], nil
		}
		return "", "", errors.New("has an unclosed quote")
	}
	end := strings.IndexByte(s, '.')
	if end < 0 {
		end = len(s)
	}
	ident = s[:end]
	if ident == "" || strings.ContainsAny(ident, "\" \t\r\n") {
		return "", "", errors.New("must be schema.table, each part a name or a double-quoted name")
	}
	return foldASCII(ident), s[end:], nil
}

// foldASCII lower-cases A to Z only, as Postgres folds an unquoted
// identifier; other letters keep their case.
func foldASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// printedName is schema.name as Postgres prints it (quote_ident).
func printedName(schema, name string) string {
	return quoteIdent(schema) + "." + quoteIdent(name)
}

// quoteIdent quotes an identifier exactly when Postgres's quote_ident does:
// anything but lower-case letters, digits, _ and $ (not leading), or a
// keyword that is not unreserved.
func quoteIdent(s string) string {
	plain := s != "" && !quotedKeywords[s]
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case (r >= '0' && r <= '9') || r == '$':
			plain = plain && i > 0
		default:
			plain = false
		}
	}
	if plain {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// quotedKeywords are Postgres's reserved, type/function-name and
// column-name keywords (kwlist.h, up to version 17): quote_ident quotes
// them. A word quoted here that an older server leaves bare is still a
// valid name.
var quotedKeywords = func() map[string]bool {
	//nolint:misspell // analyse is a Postgres keyword
	words := strings.Fields(`all analyse analyze and any array as asc asymmetric both case cast check collate
		column constraint create current_catalog current_date current_role current_time current_timestamp
		current_user default deferrable desc distinct do else end except false fetch for foreign from grant
		group having in initially intersect into lateral leading limit localtime localtimestamp not null
		offset on only or order placing primary references returning select session_user some symmetric
		system_user table then to trailing true union unique user using variadic when where window with
		authorization binary collation concurrently cross current_schema freeze full ilike inner is isnull
		join left like natural notnull outer overlaps right similar tablesample verbose
		between bigint bit boolean char character coalesce dec decimal exists extract float greatest grouping
		inout int integer interval json json_array json_arrayagg json_object json_objectagg json_scalar
		json_serialize least national nchar none normalize numeric out overlay position precision real row
		setof smallint substring time timestamp treat trim values varchar xmlattributes xmlconcat xmlelement
		xmlexists xmlforest xmlnamespaces xmlparse xmlpi xmlroot xmlserialize xmltable
		json_exists json_query json_table json_value merge_action`)
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}()
