package child

import (
	"bytes"
	"errors"
	"strings"
)

// errNoStart: the start time of a process cannot be read (it is gone, or
// the OS gives none).
var errNoStart = errors.New("child: process start time unknown")

// statStartField is starttime's index in /proc/<pid>/stat after the
// command's closing parenthesis: field 22 of the line, where the fields
// after the command start at field 3 (state).
const statStartField = 22 - 3

// parseStatStart reads starttime (clock ticks since boot) from a Linux
// /proc/<pid>/stat line. The command, in parentheses, may hold spaces and
// parentheses itself, so the fields are read after its last ')'.
func parseStatStart(stat []byte) (string, error) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return "", errNoStart
	}
	fields := strings.Fields(string(stat[i+1:]))
	if len(fields) <= statStartField {
		return "", errNoStart
	}
	v := fields[statStartField]
	for _, c := range v {
		if c < '0' || c > '9' {
			return "", errNoStart
		}
	}
	return v, nil
}
