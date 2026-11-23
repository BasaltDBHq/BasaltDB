// Package contractdoc reads the contract for the tests that check the code
// against it. The contract is CONTRACT.md, an index, and the section files
// under contract/ that the index lists.
package contractdoc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Index is the contract's index file, at the root of the repository.
const Index = "CONTRACT.md"

// Dir holds the contract's section files, next to the index.
const Dir = "contract"

var sectionLink = regexp.MustCompile(`\]\(contract/([a-z0-9-]+\.md)\)`)

// Root is the repository root: the nearest directory at or above the working
// directory that holds the index. A test runs in its package's directory.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, Index)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("contractdoc: no " + Index + " at or above the working directory")
		}
		dir = parent
	}
}

// Files lists the section files in the order the index first links them.
func Files(index []byte) []string {
	var files []string
	seen := map[string]bool{}
	for _, m := range sectionLink.FindAllSubmatch(index, -1) {
		if name := string(m[1]); !seen[name] {
			seen[name] = true
			files = append(files, name)
		}
	}
	return files
}

// Read returns the whole contract as one text: the index, then every section
// file in the index's order, a blank line between files. The headings keep
// the levels they had in one file, so a section that continues in a second
// file still sits under its "## " heading.
func Read() ([]byte, error) {
	root, err := Root()
	if err != nil {
		return nil, err
	}
	text, err := os.ReadFile(filepath.Join(root, Index))
	if err != nil {
		return nil, err
	}
	files := Files(text)
	if len(files) == 0 {
		return nil, errors.New("contractdoc: " + Index + " lists no section files")
	}
	for _, name := range files {
		part, err := os.ReadFile(filepath.Join(root, Dir, name))
		if err != nil {
			return nil, fmt.Errorf("contractdoc: %s lists %s: %w", Index, name, err)
		}
		text = append(append(text, '\n'), part...)
	}
	return text, nil
}
