package privdrop

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// threadStatus is what Linux's /proc/<pid>/task/<tid>/status says about one
// thread's credentials.
type threadStatus struct {
	// UIDs and GIDs are real, effective, saved and filesystem ids.
	UIDs, GIDs []uint32
	Groups     []uint32
	NoNewPrivs bool
	// CapPrm, CapEff and CapAmb are the thread's permitted, effective and
	// ambient capability sets, as hex masks.
	CapPrm, CapEff, CapAmb uint64
}

// idFields are a status line's real, effective, saved and filesystem ids.
const idFields = 4

// parseStatus reads the fields of a /proc status file Verify checks. A
// missing field is an error: a kernel that does not report it cannot be
// verified.
func parseStatus(text string) (threadStatus, error) {
	var st threadStatus
	seen := map[string]bool{}
	for line := range strings.SplitSeq(text, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		var err error
		switch key {
		case "Uid":
			st.UIDs, err = parseIDs(val, idFields)
		case "Gid":
			st.GIDs, err = parseIDs(val, idFields)
		case "Groups":
			st.Groups, err = parseIDs(val, -1)
		case "NoNewPrivs":
			st.NoNewPrivs = val == "1"
		case "CapPrm":
			st.CapPrm, err = strconv.ParseUint(val, 16, 64)
		case "CapEff":
			st.CapEff, err = strconv.ParseUint(val, 16, 64)
		case "CapAmb":
			st.CapAmb, err = strconv.ParseUint(val, 16, 64)
		default:
			continue
		}
		if err != nil {
			return st, fmt.Errorf("%s: %w", key, err)
		}
		seen[key] = true
	}
	for _, k := range []string{"Uid", "Gid", "Groups", "NoNewPrivs", "CapPrm", "CapEff", "CapAmb"} {
		if !seen[k] {
			return st, fmt.Errorf("no %s line", k)
		}
	}
	return st, nil
}

// parseIDs parses whitespace-separated ids; n >= 0 wants exactly n of them.
func parseIDs(val string, n int) ([]uint32, error) {
	fields := strings.Fields(val)
	if n >= 0 && len(fields) != n {
		return nil, fmt.Errorf("want %d ids, got %q", n, val)
	}
	ids := make([]uint32, 0, len(fields))
	for _, f := range fields {
		id, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			return nil, err
		}
		ids = append(ids, uint32(id))
	}
	return ids, nil
}

// check says what is wrong with one thread for a, or nil: every uid and gid
// (real, effective, saved, filesystem) must be a's, the groups a's, no
// capability left, and no_new_privs set.
func (st threadStatus) check(a Account) error {
	var problems []string
	for _, id := range st.UIDs {
		if id != a.UID {
			problems = append(problems, fmt.Sprintf("uids %v, want all %d", st.UIDs, a.UID))
			break
		}
	}
	for _, id := range st.GIDs {
		if id != a.GID {
			problems = append(problems, fmt.Sprintf("gids %v, want all %d", st.GIDs, a.GID))
			break
		}
	}
	if !sameGroups(st.Groups, a.Groups) {
		problems = append(problems, fmt.Sprintf("groups %v, want %v", st.Groups, a.Groups))
	}
	if st.CapPrm != 0 || st.CapEff != 0 || st.CapAmb != 0 {
		problems = append(problems, fmt.Sprintf("capabilities left (permitted %x, effective %x, ambient %x)", st.CapPrm, st.CapEff, st.CapAmb))
	}
	if !st.NoNewPrivs {
		problems = append(problems, "no_new_privs is not set")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}
