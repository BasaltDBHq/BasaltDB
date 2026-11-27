package sqllang

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// limitText is the revision a statement that ran into a limit asks for, by
// the QUERY_TIMEOUT reason.
var limitText = map[string]string{
	guidance.ReasonRowLimit: "Add a LIMIT or a narrower WHERE so the call returns fewer rows, then call it again.",
	guidance.ReasonRowTooLarge: "One row is too large to read whole: select fewer columns, the size of a large one " +
		"(length(col)) or a slice of it (substr(col, 1, 100000)), then call it again.",
	guidance.ReasonSizeLimit: "Select fewer or shorter columns (for example left(col, 200)) or fewer rows so the result stays under 16 MiB, then call it again.",
}

// timeoutText is the revision a statement that ran out of time asks for.
const timeoutText = "Narrow the statement (a tighter WHERE, fewer joins, a LIMIT) so it finishes in time, then call it again."

// LimitText is the revision a statement that ran into a limit asks for, by
// the QUERY_TIMEOUT reason; any other reason is the statement timeout's.
func (Language) LimitText(reason string) string {
	if text, ok := limitText[reason]; ok {
		return text
	}
	return timeoutText
}

var staleDetail = regexp.MustCompile(`^STALE_READ: (.+?) (\{.*\}) read at xmin \d+, now \d+`)

// StaleTarget reads the table and key a STALE_READ message names. The
// guard's detail names them (`public.leads {"id": 42} read at xmin 7, now
// 9`). Decided here, provisionally: the engine parses the detail, whose
// format a test against a real guard pins, instead of a guard migration to
// a JSON detail.
func (Language) StaleTarget(message string) (target string, key map[string]any, err error) {
	m := staleDetail.FindStringSubmatch(message)
	if m == nil {
		return "", nil, fmt.Errorf("cannot read the table and key from the stale read detail %q", message)
	}
	dec := json.NewDecoder(strings.NewReader(m[2]))
	dec.UseNumber()
	if err := dec.Decode(&key); err != nil || len(key) == 0 {
		return "", nil, fmt.Errorf("cannot read the key of the stale read: %q", m[2])
	}
	return m[1], key, nil
}

var deniedTable = regexp.MustCompile(`permission denied for (?:table|relation) (\S+)`)

// DeniedTarget is the table a Postgres permission-denied message names, and
// false when it names none.
func (Language) DeniedTarget(message string) (string, bool) {
	if m := deniedTable.FindStringSubmatch(message); m != nil {
		return m[1], true
	}
	return "", false
}

var rlsRefusal = regexp.MustCompile(`(?:new row violates|query would be affected by) row-level security policy(?: "(?:[^"]|"")*")?(?: \([A-Za-z ]+\))?(?: for table (?:"((?:[^"]|"")+)"|(\S+)))?`)

// RLSRefusal is the table a Postgres row-level security refusal ("new row
// violates row-level security policy for table "leads"", and the USING and
// WITH CHECK forms) names, "" when it names none, and false when the message
// is not that refusal.
func (Language) RLSRefusal(message string) (string, bool) {
	m := rlsRefusal.FindStringSubmatch(message)
	if m == nil {
		return "", false
	}
	if m[1] != "" {
		return strings.ReplaceAll(m[1], `""`, `"`), true
	}
	return m[2], true
}

var noPrimaryKey = regexp.MustCompile(`table (\S+) has no primary key`)

// NoKeyTarget is the table the guard's refusal of a table without a
// primary key names, and false when it names none.
func (Language) NoKeyTarget(message string) (string, bool) {
	if m := noPrimaryKey.FindStringSubmatch(message); m != nil {
		return m[1], true
	}
	return "", false
}
