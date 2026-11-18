package crash

import (
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Scrubber removes what must never reach a crash report. It works in two
// layers. The report is built from an allowlist (a command name, a panic
// type, a stack of function names and file positions), so free text never
// enters it. What does enter is then scrubbed anyway: the home directory,
// the values of the environment, the host name, URLs, key=value secrets,
// e-mail and IP addresses.
type Scrubber struct {
	home     string
	hostName string
	env      []string
}

// minEnvValue is the shortest environment value that is replaced where it
// appears: shorter ones ("1", "on") would damage ordinary text.
const minEnvValue = 6

// NewScrubber returns a scrubber for a process whose home directory is home,
// host name is hostName and environment is env ("KEY=value" entries).
func NewScrubber(home, hostName string, env []string) *Scrubber {
	s := &Scrubber{home: strings.TrimRight(home, `/\`), hostName: hostName}
	for _, kv := range env {
		_, v, ok := strings.Cut(kv, "=")
		if ok && len(v) >= minEnvValue {
			s.env = append(s.env, v)
		}
	}
	// Longest first, so a value that contains another is replaced whole.
	sort.Slice(s.env, func(i, j int) bool { return len(s.env[i]) > len(s.env[j]) })
	return s
}

// OSScrubber is the scrubber for this process.
func OSScrubber() *Scrubber {
	home, _ := os.UserHomeDir()
	host, _ := os.Hostname()
	return NewScrubber(home, host, os.Environ())
}

var (
	reURL        = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>]+`)
	reKeyValue   = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|sslkey|sslpassword|user|host|hostaddr|dbname|port|service)\s*=\s*('[^']*'|"[^"]*"|\S+)`)
	reEmail      = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reIPv4       = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`)
	reIPv6       = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b`)
	reHomeDir    = regexp.MustCompile(`(?:/Users|/home)/[^/\s:]+|[A-Za-z]:\\Users\\[^\\\s:]+|/root\b`)
	reQuoted     = regexp.MustCompile("'[^']*'|\"[^\"]*\"|`[^`]*`")
	reSQLKeyword = regexp.MustCompile(`(?is)\b(select\b.*\bfrom|insert\s+into|update\b.*\bset|delete\s+from|create\s+(table|index|role|user)|alter\s+(table|role|user)|drop\s+(table|schema|role|user)|truncate|\bwhere\b)`)
)

// Text scrubs one piece of free text (a panic message).
func (s *Scrubber) Text(in string) string {
	if reSQLKeyword.MatchString(in) {
		return redacted
	}
	return s.common(reQuoted.ReplaceAllString(in, quotedMark))
}

// redacted, quotedMark and the other marks are what scrubbed text becomes.
const (
	redacted   = "<redacted>"
	quotedMark = "<text>"
)

// common is the scrubbing both free text and stack lines get.
func (s *Scrubber) common(in string) string {
	out := in
	if s.home != "" {
		out = strings.ReplaceAll(out, s.home, "~")
	}
	out = reHomeDir.ReplaceAllString(out, "~")
	if len(s.hostName) >= minEnvValue-2 {
		out = strings.ReplaceAll(out, s.hostName, "<host>")
	}
	for _, v := range s.env {
		out = strings.ReplaceAll(out, v, "<env>")
	}
	out = reURL.ReplaceAllString(out, "<url>")
	out = reKeyValue.ReplaceAllString(out, "$1="+redacted)
	out = reEmail.ReplaceAllString(out, "<email>")
	out = reIPv4.ReplaceAllString(out, "<host>")
	return reIPv6.ReplaceAllString(out, "<host>")
}

var (
	reGoroutine = regexp.MustCompile(`^goroutine \d+ \[[a-z0-9 ,]+\]:$`)
	reFuncLine  = regexp.MustCompile(`^[A-Za-z0-9_/*()\[\]{}·,\-]*[A-Za-z0-9_]\.[A-Za-z0-9_./*()\[\]{}·,\-]+$`)
	reFileLine  = regexp.MustCompile(`^\t(.+):(\d+)(?: \+0x[0-9a-f]+)?$`)
	reCreatedBy = regexp.MustCompile(`^created by ([A-Za-z0-9_./*()\[\]{}·,\-]+)(?: in goroutine \d+)?$`)
)

// pathParts is how many trailing path components of a source file a report
// keeps: enough to find the file in the repository, too few to carry a
// directory the person named.
const pathParts = 3

// elided is the line the Go runtime prints where it left frames out.
const elided = "...additional frames elided..."

// Stack scrubs the text of runtime/debug.Stack. Only lines of a known shape
// survive: the goroutine header, a function without its arguments, a source
// position cut to its last components, and "created by". Anything else, such
// as a "panic: value" line, is dropped.
func (s *Scrubber) Stack(raw string) string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if kept, ok := s.stackLine(line); ok {
			out = append(out, kept)
		}
	}
	return strings.Join(out, "\n")
}

func (s *Scrubber) stackLine(line string) (string, bool) {
	switch {
	case line == elided, reGoroutine.MatchString(line):
		return line, true
	case reFileLine.MatchString(line):
		m := reFileLine.FindStringSubmatch(line)
		return "\t" + s.shortPath(m[1]) + ":" + m[2], true
	case reCreatedBy.MatchString(line):
		return "created by " + s.common(reCreatedBy.FindStringSubmatch(line)[1]), true
	case strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " ") || line == "":
		return "", false
	}
	// A function line ends with its argument list, which holds values: it
	// is cut before the name is checked.
	if strings.HasSuffix(line, ")") {
		if i := strings.LastIndex(line, "("); i > 0 {
			line = line[:i] + "(...)"
		}
	}
	if !reFuncLine.MatchString(line) {
		return "", false
	}
	return s.common(line), true
}

// shortPath keeps the last pathParts components of a source file, after the
// home directory is scrubbed.
func (s *Scrubber) shortPath(p string) string {
	p = strings.ReplaceAll(s.common(p), `\`, "/")
	parts := strings.Split(path.Clean(p), "/")
	if len(parts) > pathParts {
		parts = parts[len(parts)-pathParts:]
	}
	return strings.Join(parts, "/")
}
