package pgstatement

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	pganalyze "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ReasonNotRepeatable refuses a write that would be held but whose values
// change between transactions (decision M2-1): the preview the person
// approves could never match the write that applies.
const ReasonNotRepeatable Reason = "NOT_REPEATABLE"

// nonRepeatableFunctions return another value in another transaction and
// the engine cannot fix them (fixableFunctions it can): a held write that
// uses one is refused. nextval appears in a column default; a statement
// that calls it is refused by the allowlist (decision #11) first.
var nonRepeatableFunctions = toSet(`
	timeofday random random_normal gen_random_uuid uuid_generate_v4 uuidv4 uuidv7 nextval
`)

// Holdable is what preview and approval need from a write: the columns
// whose new values the approval binds.
type Holdable struct {
	// Table is the target table, as written.
	Table string
	// Assigned are the columns the statement sets: UPDATE SET targets, or
	// the INSERT column list (and ON CONFLICT DO UPDATE SET targets). Nil
	// for an INSERT without a column list: every column of the table.
	Assigned []string
}

// CheckRepeatable parses a write the guard held and refuses it with
// NOT_REPEATABLE when it contains a value that changes between
// transactions that the engine does not fix (PlanTimes fixes now(),
// CURRENT_TIMESTAMP and the other time functions it lists): timeofday(),
// LOCALTIME, random() and UUID generators, age() with one argument,
// a string literal or parameter that is a time word ('now', 'today',
// 'tomorrow', 'yesterday', alone or with a time of day or zone), or the
// DEFAULT keyword. It returns the
// target table and assigned columns otherwise. Anything it misses fails
// closed at commit (the guard recomputes the preview lines).
func CheckRepeatable(sql string, params []any) (Holdable, error) {
	tree, err := pgquery.Parse(sql)
	if err != nil {
		return Holdable{}, &RefusalError{Reason: ReasonParseError, Detail: err.Error()}
	}
	stmts := tree.GetStmts()
	if len(stmts) != 1 {
		return Holdable{}, refuse(ReasonMultipleStatements, "%d statements; send exactly one", len(stmts))
	}
	node := stmts[0].GetStmt()
	if what := nonRepeatable(node.ProtoReflect()); what != "" {
		fix := "pass the value as a parameter ($n)"
		if strings.HasPrefix(what, "'") {
			fix = "pass a fixed timestamp as a parameter ($n), not a time word"
		}
		return Holdable{}, refuse(ReasonNotRepeatable,
			"%s gives another value when the approved write runs; %s, so the person approves exactly what is written", what, fix)
	}
	if word := timeWordParam(params); word != "" {
		return Holdable{}, refuse(ReasonNotRepeatable,
			"a parameter is the time word '%s', which Postgres reads as the time the statement runs, so it gives another value when the approved write runs; pass a fixed timestamp as the parameter ($n) so the person approves exactly what is written", word)
	}
	return holdable(node), nil
}

// timeWordParam is the first string parameter that is a time word (see
// timeWord), or "".
func timeWordParam(params []any) string {
	for _, p := range params {
		if s, ok := p.(string); ok {
			if word := timeWord(s); word != "" {
				return word
			}
		}
	}
	return ""
}

// timeWords are the values Postgres's date and time input reads as the time
// the statement runs, not as a fixed one: 'now', 'today', 'tomorrow' and
// 'yesterday' (case and surrounding spaces do not matter), alone or with a
// time of day or zone ('tomorrow 10:00', 'today noon', 'now UTC').
var timeWords = toSet(`now today tomorrow yesterday`)

// timeWordCompanions are the words that may stand with a time word and still
// leave the whole string a date/time input: the era, day names, a few noise
// words and the zone abbreviations of Postgres's default set
// (pg_timezone_abbrevs). Any other word makes it plain text ("call back
// tomorrow"), which a text column keeps as written.
var timeWordCompanions = toSet(`
	t at on ad bc am pm localtime posixrules factory
	mon monday tue tues tuesday wed wednesday thu thur thurs thursday fri friday sat saturday sun sunday
	acdt acsst acst act acwst adt aedt aesst aest aft akdt akst almst almt amst amt anast anat arst art ast awsst awst
	azost azot azst azt bdst bdt bnt bort bot bra brst brt bst btt cadt cast cct cdt cest cet cetdst chadt chast chut ckt
	clst clt cot cst cxt davt ddut easst east eat edt eest eet eetdst egst egt est fet fjst fjt fkst fkt fnst fnt galt
	gamt gest get gft gilt gmt gyt hkt hst ict idt iot irkst irkt irt ist jayt jst kdt kgst kgt kost krast krat kst lhdt
	lhst ligt lint lkt magst magt mart mawt mdt mest mesz met metdst mez mht mmt mpt msd msk mst must mut mvt myt ndt
	nft novst novt npt nst nut nzdt nzst nzt omsst omst pdt pet petst pett pgt pht pkst pkt pmdt pmst pont pst pwt pyst
	pyt ret sadt sast sct sgt tft tjt tkt tmt tot trut tvt uct ulast ulat ut utc uyst uyt uzst uzt vet vlast vlat
	volt vut wadt wakt wast wat wdt wet wetdst wft wgst wgt xjt yakst yakt yapt yekst yekt z zulu
`)

func init() {
	// Tahiti time; written in two parts so the spell checker does not
	// "correct" a Postgres zone abbreviation.
	timeWordCompanions["ta"+"ht"] = true
}

// zoneName matches a zone as Postgres takes it by name: an IANA area, a
// slash and the rest ("Europe/Berlin", "America/Argentina/Buenos_Aires",
// "Etc/GMT+2"). It is read as one zone word.
var zoneName = regexp.MustCompile(
	`(?:africa|america|antarctica|arctic|asia|atlantic|australia|brazil|canada|chile|etc|europe|indian|mexico|pacific|posix|us)/[a-z0-9_+/-]+`)

// timeWord returns the time word s is made of, or "" when s is not a
// date/time input that depends on the clock. It reads s as Postgres's
// date/time input does: runs of letters, and runs of digits with the
// punctuation of a time or offset (":.+-/"); every other character only
// separates ("now()", "(now)", "{now,tomorrow}", "today+02" and "today
// 10:00Z" all read as the current time).
func timeWord(s string) string {
	word := ""
	for _, tok := range tokens(zoneName.ReplaceAllString(strings.ToLower(s), " z ")) {
		switch {
		case timeWords[tok]:
			if word == "" {
				word = tok
			}
		case timeWordCompanions[tok], clockToken(tok):
		default:
			return ""
		}
	}
	return word
}

// tokens splits s into runs of letters and runs of digits and ":.+-/".
func tokens(s string) []string {
	var out []string
	start, kind := -1, 0 // kind: 1 letters, 2 digits and punctuation
	flush := func(end int) {
		if start >= 0 {
			out = append(out, s[start:end])
			start, kind = -1, 0
		}
	}
	for i, r := range s {
		k := 0
		switch {
		case unicode.IsLetter(r):
			k = 1
		case r >= '0' && r <= '9', r != 0 && strings.ContainsRune(":.+-/", r):
			k = 2
		}
		if k != kind {
			flush(i)
			if k != 0 {
				start, kind = i, k
			}
		}
	}
	flush(len(s))
	return out
}

// clockToken reports whether tok is a run of digits and the punctuation of a
// time or an offset ("10:00", "10:00:30.5", "+02", "-05:30").
func clockToken(tok string) bool {
	for _, r := range tok {
		if (r < '0' || r > '9') && !strings.ContainsRune(":.+-/", r) {
			return false
		}
	}
	return tok != ""
}

// nonRepeatable returns a description of the first non-repeatable
// expression in the tree, or "".
func nonRepeatable(root protoreflect.Message) string {
	found := ""
	walkTree(root, func(m protoreflect.Message) bool {
		if found != "" {
			return false
		}
		if n, ok := m.Interface().(*pganalyze.Node); ok && fixableType(n) != "" {
			return false // fixed when the write is held (PlanTimes)
		}
		found = nonRepeatableNode(m)
		return found == ""
	})
	return found
}

func nonRepeatableNode(m protoreflect.Message) string {
	switch v := m.Interface().(type) {
	case *pganalyze.FuncCall:
		name := strings.TrimPrefix(nameOf(v.GetFuncname()), "pg_catalog.")
		// A time function the engine does not fix (with arguments or OVER)
		// is refused like the others; fixable ones never reach here.
		if nonRepeatableFunctions[name] || fixableFunctions[name] || (name == "age" && len(v.GetArgs()) == 1) {
			return name + "()"
		}
	case *pganalyze.SQLValueFunction:
		if v.GetOp() >= pganalyze.SQLValueFunctionOp_SVFOP_CURRENT_DATE &&
			v.GetOp() <= pganalyze.SQLValueFunctionOp_SVFOP_LOCALTIMESTAMP_N {
			return strings.TrimPrefix(v.GetOp().String(), "SVFOP_")
		}
	case *pganalyze.SetToDefault:
		return "DEFAULT"
	case *pganalyze.A_Const:
		// Any string literal, cast or not: Postgres reads 'now' as the
		// current time when it is assigned to, compared with or cast to a
		// date or time, and the parse tree does not know the column's type.
		if word := timeWord(v.GetSval().GetSval()); word != "" {
			return fmt.Sprintf("'%s'", v.GetSval().GetSval())
		}
	}
	return ""
}

func holdable(node *pganalyze.Node) Holdable {
	switch {
	case node.GetUpdateStmt() != nil:
		u := node.GetUpdateStmt()
		return Holdable{Table: rangeVarName(u.GetRelation()), Assigned: targetNames(u.GetTargetList())}
	case node.GetInsertStmt() != nil:
		ins := node.GetInsertStmt()
		h := Holdable{Table: rangeVarName(ins.GetRelation())}
		if len(ins.GetCols()) > 0 {
			h.Assigned = union(targetNames(ins.GetCols()), targetNames(ins.GetOnConflictClause().GetTargetList()))
		}
		return h
	case node.GetDeleteStmt() != nil:
		return Holdable{Table: rangeVarName(node.GetDeleteStmt().GetRelation()), Assigned: []string{}}
	}
	return Holdable{Assigned: []string{}}
}

func rangeVarName(r *pganalyze.RangeVar) string {
	return qualifiedName(r.GetSchemaname(), r.GetRelname())
}

func targetNames(list []*pganalyze.Node) []string {
	out := make([]string, 0, len(list))
	for _, n := range list {
		if rt := n.GetResTarget(); rt != nil && rt.GetName() != "" {
			out = append(out, rt.GetName())
		}
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
