// Package mcpcontract holds the MCP tool contracts the engine serves: one
// JSON file per tool under tools/, embedded so the engine lists the
// contract's input schema verbatim. See CONTRACT.md, "Process: contract first".
package mcpcontract

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Tool statuses (CONTRACT.md).
const (
	StatusImplemented = "IMPLEMENTED"
	StatusPlanned     = "PLANNED"
)

//go:embed tools/*.json
var toolFiles embed.FS

// Tool is one tool contract, as stored in tools/<name>.json.
type Tool struct {
	Name         string         `json:"name"`
	Status       string         `json:"status"`
	Milestone    string         `json:"milestone"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema"`
	Errors       []string       `json:"errors"`

	// File is the embedded file the contract was read from.
	File string `json:"-"`
}

// Load returns every tool contract, sorted by name.
func Load() ([]Tool, error) {
	entries, err := toolFiles.ReadDir("tools")
	if err != nil {
		return nil, fmt.Errorf("read tool contracts: %w", err)
	}
	tools := make([]Tool, 0, len(entries))
	for _, e := range entries {
		file := path.Join("tools", e.Name())
		raw, err := toolFiles.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		var t Tool
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&t); err != nil {
			return nil, fmt.Errorf("decode %s: %w", file, err)
		}
		t.File = file
		tools = append(tools, t)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

// MustLoad is Load for process start: the contracts are embedded, so a
// failure is a build defect.
func MustLoad() []Tool {
	tools, err := Load()
	if err != nil {
		panic(err)
	}
	return tools
}

// Find returns the contract named name.
func Find(tools []Tool, name string) (Tool, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// CheckServed compares the tools a server lists with the contracts: every
// served tool needs a contract, and every IMPLEMENTED contract must be served.
func CheckServed(tools []Tool, served []string) error {
	var errs []error
	servedSet := make(map[string]bool, len(served))
	for _, name := range served {
		servedSet[name] = true
		if _, ok := Find(tools, name); !ok {
			errs = append(errs, fmt.Errorf("tool %q is served but has no contract in api/mcp/tools", name))
		}
	}
	for _, t := range tools {
		if t.Status == StatusImplemented && !servedSet[t.Name] {
			errs = append(errs, fmt.Errorf("tool %q is %s but not served", t.Name, StatusImplemented))
		}
	}
	return errors.Join(errs...)
}
