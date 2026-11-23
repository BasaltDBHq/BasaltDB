// Package mcptest checks what the engine puts on the wire against the rules
// of CONTRACT.md that JSON Schema cannot express. It is test support: the
// engine's tests call it on every personMessage they see.
package mcptest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// PersonMessageLimit is the most characters a personMessage holds, not
// counting its URL lines (CONTRACT.md, Links in personMessage).
const PersonMessageLimit = 500

var (
	urlPattern     = regexp.MustCompile(`https?://\S+`)
	urlLine        = regexp.MustCompile(`(?m)^https?://\S+\n?`)
	wholeURL       = regexp.MustCompile(`^https?://\S+$`)
	urlStop        = regexp.MustCompile("[.,;:)>\"'`]$")
	markdownAround = regexp.MustCompile("\\]\\(|<https?:|`https?:|\\*https?:|_https?:")
	labelForbidden = regexp.MustCompile("[\\[\\]()<>`*_]")
)

// Require fails t when message or links break CONTRACT.md, Links in
// personMessage. See Problem.
func Require(t *testing.T, message string, links []toolresult.Link) {
	t.Helper()
	require.NoError(t, Problem(message, links), "personMessage %q", message)
}

// Problem is the first rule message or links break, or nil: lines separated
// by \n, the 500-character limit that does not count URL lines (the URL and
// its line break), each URL alone on its line with an empty line around it,
// no Markdown around a URL, and links next to the message exactly when it
// holds a URL, one entry per URL in order, byte for byte, each with a valid
// label.
func Problem(message string, links []toolresult.Link) error {
	if message == "" && len(links) > 0 {
		return errors.New("links without a personMessage")
	}
	if strings.Contains(message, "\r") {
		return errors.New("lines are separated by \\n only")
	}
	lines := strings.Split(message, "\n")
	var urls []string
	for i, line := range lines {
		if !urlPattern.MatchString(line) {
			continue
		}
		urls = append(urls, line)
		if !wholeURL.MatchString(line) || urlStop.MatchString(line) {
			return fmt.Errorf("a URL has its line to itself, nothing before or after it: %q", line)
		}
		if i > 0 && lines[i-1] != "" {
			return fmt.Errorf("no empty line before the URL %q", line)
		}
		if i < len(lines)-1 && lines[i+1] != "" {
			return fmt.Errorf("no empty line after the URL %q", line)
		}
	}
	if n := len([]rune(urlLine.ReplaceAllString(message, ""))); n > PersonMessageLimit {
		return fmt.Errorf("%d characters without the URL lines, the limit is %d", n, PersonMessageLimit)
	}
	if markdownAround.MatchString(message) {
		return errors.New("a URL has Markdown around it")
	}
	if len(links) != len(urls) {
		return fmt.Errorf("%d links for %d URLs: links are present exactly when the message holds a URL", len(links), len(urls))
	}
	for i, l := range links {
		if l.URL != urls[i] {
			return fmt.Errorf("links[%d].url %q is not the URL %q", i, l.URL, urls[i])
		}
		if err := labelProblem(l.Label); err != nil {
			return err
		}
	}
	return nil
}

func labelProblem(label string) error {
	if n := len([]rune(label)); n < 1 || n > 80 {
		return fmt.Errorf("label %q: 1 to 80 characters", label)
	}
	if urlPattern.MatchString(label) || labelForbidden.MatchString(label) {
		return fmt.Errorf("label %q: no URL and no Markdown character", label)
	}
	for _, r := range label {
		if unicode.IsControl(r) || lineBreakOrBidi(r) {
			return fmt.Errorf("label %q: no control character, line break or bidirectional control", label)
		}
	}
	return nil
}

// The Unicode line breaks and bidirectional controls a label never holds.
const (
	lineSeparator      rune = 0x2028
	paragraphSeparator rune = 0x2029
	embeddingFirst     rune = 0x202a
	overrideLast       rune = 0x202e
	isolateFirst       rune = 0x2066
	isolateLast        rune = 0x2069
)

// lineBreakOrBidi reports U+2028, U+2029, the bidirectional embeddings and
// overrides (U+202A to U+202E) and the isolates (U+2066 to U+2069).
func lineBreakOrBidi(r rune) bool {
	return r == lineSeparator || r == paragraphSeparator ||
		(r >= embeddingFirst && r <= overrideLast) || (r >= isolateFirst && r <= isolateLast)
}

// LinksOf is the links array of a decoded tool result or error body, nil when
// it has none.
func LinksOf(t *testing.T, body map[string]any) []toolresult.Link {
	t.Helper()
	raw, ok := body["links"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(raw)
	require.NoError(t, err)
	var out []toolresult.Link
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}
