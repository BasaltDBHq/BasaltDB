package shim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

// The request file beside a hash link (CONTRACT.md, The request file and
// pasted blocks): the engine puts the request in requestFile.text; the shim,
// which runs as the agent's OS user, writes it to a file on the agent's
// machine and adds its path, so the agent attaches the file instead of
// retyping tens of kilobytes of base64url.
const (
	requestFilesKeep = 24 * time.Hour
	requestDirMode   = 0o700
	requestFileMode  = 0o600
)

var (
	requestFileName = regexp.MustCompile(`^basalt-(approval|revert)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.txt$`)
	requestFileText = regexp.MustCompile(`^2\.[A-Za-z0-9_-]+$`)
	requestFileKey  = []byte(`requestFile`)
)

// requestFiles writes request files under dir; dir "" writes none.
type requestFiles struct {
	dir string
	now func() time.Time
}

// defaultRequestFiles writes under <user cache dir>/basalt/requests; none
// when the cache dir is unknown.
func defaultRequestFiles() requestFiles {
	cache, err := os.UserCacheDir()
	if err != nil {
		return requestFiles{now: time.Now}
	}
	return requestFiles{dir: filepath.Join(cache, "basalt", "requests"), now: time.Now}
}

// attach returns line with path added to every requestFile in its tool
// result, or line unchanged when it carries none or a file cannot be
// written: the agent then copies text, as the contract allows.
func (f requestFiles) attach(line []byte) []byte {
	if f.dir == "" || !bytes.Contains(line, requestFileKey) {
		return line
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var msg map[string]any
	if dec.Decode(&msg) != nil {
		return line
	}
	result, ok := msg["result"].(map[string]any)
	if !ok {
		return line
	}
	content, ok := result["content"].([]any)
	if !ok {
		return line
	}
	changed := false
	for _, c := range content {
		item, ok := c.(map[string]any)
		if !ok {
			continue
		}
		text, ok := item["text"].(string)
		if !ok || !strings.Contains(text, string(requestFileKey)) {
			continue
		}
		if withPaths, ok := f.attachText(text); ok {
			item["text"], changed = withPaths, true
		}
	}
	if !changed {
		return line
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(msg); err != nil {
		return line
	}
	return bytes.TrimRight(out.Bytes(), "\n")
}

// attachText writes each request file the tool result text names and adds
// its path right after its fileName, keeping the rest of the text as the
// engine wrote it.
func (f requestFiles) attachText(text string) (string, bool) {
	var body any
	if json.Unmarshal([]byte(text), &body) != nil {
		return "", false
	}
	files := map[string]string{}
	collectRequestFiles(body, files)
	if len(files) == 0 {
		return "", false
	}
	f.prune()
	for name, content := range files {
		path, err := f.write(name, content)
		if err != nil {
			return "", false
		}
		if text, err = insertPath(text, name, path); err != nil {
			return "", false
		}
	}
	return text, true
}

// collectRequestFiles finds the requestFile objects of a tool result, only
// where the contract puts them (CONTRACT.md, The request file and pasted
// blocks): beside approvalUrl in APPROVAL_REQUIRED's approval, beside
// revertUrl at the top of revert_plan and request_revert, and in each
// list_pending item. Each must sit beside the hash link of its own text, so
// a requestFile-shaped value in data (a jsonb column a query returned) is
// never acted on. File name to text.
func collectRequestFiles(v any, files map[string]string) {
	body, ok := v.(map[string]any)
	if !ok {
		return
	}
	if approval, ok := body["approval"].(map[string]any); ok {
		besideLink(approval, files)
	}
	besideLink(body, files)
	items, ok := body["items"].([]any)
	if !ok {
		return
	}
	for _, it := range items {
		if item, ok := it.(map[string]any); ok {
			besideLink(item, files)
		}
	}
}

// besideLink adds obj's requestFile when it is well formed and obj's
// approvalUrl or revertUrl is the hash link of its text.
func besideLink(obj map[string]any, files map[string]string) {
	rf, ok := obj["requestFile"].(map[string]any)
	if !ok {
		return
	}
	name, _ := rf["fileName"].(string)
	text, _ := rf["text"].(string)
	if !requestFileName.MatchString(name) || !requestFileText.MatchString(text) {
		return
	}
	link, _ := obj["approvalUrl"].(string)
	if link == "" {
		link, _ = obj["revertUrl"].(string)
	}
	if !strings.HasSuffix(link, "#h="+links.RequestHash(text)) {
		return
	}
	files[name] = text
}

// insertPath adds "path" after the one "fileName": "<name>", line of text,
// at the same indent. It refuses a text that holds that line more than once
// or not at all: then it cannot tell which object is the requestFile.
func insertPath(text, name, path string) (string, error) {
	quoted, err := json.Marshal(path)
	if err != nil {
		return "", err
	}
	field := `"fileName": "` + name + `",`
	if strings.Count(text, field) != 1 {
		return "", fmt.Errorf("request file %s is named %d times", name, strings.Count(text, field))
	}
	i := strings.Index(text, field)
	lineStart := strings.LastIndex(text[:i], "\n") + 1
	indent := text[lineStart:i]
	if strings.TrimSpace(indent) != "" {
		return "", fmt.Errorf("request file %s is not on a line of its own", name)
	}
	end := i + len(field)
	return text[:end] + "\n" + indent + `"path": ` + string(quoted) + "," + text[end:], nil
}

// write puts content in dir/name, mode 0600, through a temporary file so a
// reader never sees half of it.
func (f requestFiles) write(name, content string) (string, error) {
	if err := f.ownDir(); err != nil {
		return "", err
	}
	path := filepath.Join(f.dir, name)
	if err := atomicfile.Write(path, []byte(content), atomicfile.Options{Mode: requestFileMode}); err != nil {
		return "", fmt.Errorf("request file: %w", err)
	}
	return path, nil
}

// ownDir makes the request file directory, and refuses one that is a link,
// not this user's, or open to others (an XDG_CACHE_HOME pointing at a shared
// place): the files hold requests the person signs.
func (f requestFiles) ownDir() error {
	if err := os.MkdirAll(f.dir, requestDirMode); err != nil {
		return fmt.Errorf("request file dir: %w", err)
	}
	fi, err := os.Lstat(f.dir)
	if err != nil {
		return fmt.Errorf("request file dir: %w", err)
	}
	switch {
	case !fi.IsDir():
		return fmt.Errorf("request file dir %s is not a directory", f.dir)
	case ownerfile.CheckOwner(fi, ownerfile.Rules{}) != nil:
		return fmt.Errorf("request file dir %s is not this user's", f.dir)
	case fi.Mode().Perm()&^requestDirMode != 0:
		return fmt.Errorf("request file dir %s is open to other users", f.dir)
	}
	return nil
}

// prune removes request files older than requestFilesKeep. Failures are
// ignored: a file left behind is the agent's own, mode 0600.
func (f requestFiles) prune() {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return
	}
	cutoff := f.now().Add(-requestFilesKeep)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(f.dir, e.Name()))
	}
}
