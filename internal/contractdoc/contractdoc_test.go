package contractdoc_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/contractdoc"
)

var (
	heading    = regexp.MustCompile(`^(#{1,4}) (.+)$`)
	link       = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	notSlug    = regexp.MustCompile(`[^\p{L}\p{N}_\- ]`)
	indexEntry = regexp.MustCompile(`\[([^\]]+)\]\(contract/([a-z0-9-]+\.md)#[^)]+\)`)
)

// maxSectionFile keeps a section file small enough to load for one task.
// Split a file that outgrows it and list the new file in the index.
const maxSectionFile = 100 << 10

type doc struct {
	headings []string        // "## " and "### " headings, in order
	anchors  map[string]bool // the anchors GitHub gives the headings
}

// parse reads the headings of one Markdown file, outside code fences.
func parse(t *testing.T, path string) doc {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	d := doc{anchors: map[string]bool{}}
	count := map[string]int{}
	fence := false
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "```") {
			fence = !fence
		}
		m := heading.FindStringSubmatch(line)
		if fence || m == nil {
			continue
		}
		slug := strings.ReplaceAll(notSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(m[2])), ""), " ", "-")
		if n := count[slug]; n > 0 {
			d.anchors[slug+"-"+strconv.Itoa(n)] = true
		} else {
			d.anchors[slug] = true
		}
		count[slug]++
		if len(m[1]) == 2 || len(m[1]) == 3 {
			d.headings = append(d.headings, m[2])
		}
	}
	return d
}

// TestIndexListsEverySectionFile: the index and the contract directory name
// the same files, and no file has outgrown its limit.
func TestIndexListsEverySectionFile(t *testing.T) {
	t.Parallel()
	root, err := contractdoc.Root()
	require.NoError(t, err)
	index, err := os.ReadFile(filepath.Join(root, contractdoc.Index))
	require.NoError(t, err)
	entries, err := os.ReadDir(filepath.Join(root, contractdoc.Dir))
	require.NoError(t, err)
	onDisk := make([]string, 0, len(entries))
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".md" {
			continue // surface.json is the surface budget, not a section
		}
		onDisk = append(onDisk, e.Name())
		info, err := e.Info()
		require.NoError(t, err)
		require.LessOrEqual(t, info.Size(), int64(maxSectionFile), "%s is too large to load for one task: split it", e.Name())
	}
	require.ElementsMatch(t, onDisk, contractdoc.Files(index), "CONTRACT.md's Sections table and contract/ differ")
}

// TestIndexNamesEveryHeading: a reference such as (CONTRACT.md, Direct
// transport) is found through the index, so the index names every "### "
// heading of every section file, under the file that holds it.
func TestIndexNamesEveryHeading(t *testing.T) {
	t.Parallel()
	root, err := contractdoc.Root()
	require.NoError(t, err)
	index, err := os.ReadFile(filepath.Join(root, contractdoc.Index))
	require.NoError(t, err)
	listed := map[string][]string{}
	for line := range strings.SplitSeq(string(index), "\n") {
		if !strings.HasPrefix(line, "| [`") {
			continue
		}
		for _, m := range indexEntry.FindAllStringSubmatch(line, -1) {
			listed[m[2]] = append(listed[m[2]], m[1])
		}
	}
	for _, name := range contractdoc.Files(index) {
		var want []string
		for _, line := range strings.Split(readFile(t, filepath.Join(root, contractdoc.Dir, name)), "\n") {
			if text, ok := strings.CutPrefix(line, "### "); ok {
				want = append(want, text)
			}
		}
		require.Equal(t, want, listed[name], "CONTRACT.md's Sections table does not list the headings of %s", name)
	}
}

// TestLinksResolve: every relative link in the contract points at a file
// that exists and, when it names an anchor in the contract, at a heading.
func TestLinksResolve(t *testing.T) {
	t.Parallel()
	root, err := contractdoc.Root()
	require.NoError(t, err)
	index, err := os.ReadFile(filepath.Join(root, contractdoc.Index))
	require.NoError(t, err)
	files := contractdoc.Files(index)
	paths := make([]string, 0, len(files)+1)
	paths = append(paths, filepath.Join(root, contractdoc.Index))
	for _, name := range files {
		paths = append(paths, filepath.Join(root, contractdoc.Dir, name))
	}
	docs := map[string]doc{}
	for _, p := range paths {
		docs[p] = parse(t, p)
	}
	for _, p := range paths {
		for _, m := range link.FindAllStringSubmatch(stripCode(readFile(t, p)), -1) {
			target := m[1]
			// A bare word, as in the example "[label](url)", is not a path.
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") || !strings.ContainsAny(target, "./#") {
				continue
			}
			file, anchor, _ := strings.Cut(target, "#")
			dest := p
			if file != "" {
				dest = filepath.Join(filepath.Dir(p), file)
				_, err := os.Stat(dest)
				require.NoError(t, err, "%s links %s, which does not exist", filepath.Base(p), target)
			}
			if d, ok := docs[dest]; ok && anchor != "" {
				require.True(t, d.anchors[anchor], "%s links %s, which is not a heading", filepath.Base(p), target)
			}
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(raw)
}

var codeSpan = regexp.MustCompile("(?s)```.*?```|`[^`\n]*`")

// stripCode drops code fences and code spans, where "](" is not a link.
func stripCode(text string) string {
	return codeSpan.ReplaceAllString(text, "")
}

// A long link is review only ([Approvals](contract/approvals.md)): the person
// guide must not say it can be signed.
func TestApprovingGuideLongLinksAreReviewOnly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "approving.md"))
	require.NoError(t, err)
	s := string(raw)
	require.NotContains(t, s, "can only be signed as it is")
	require.Contains(t, s, "review only")
	require.Contains(t, s, "reissueLink")
}
