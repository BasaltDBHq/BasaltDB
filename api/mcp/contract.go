// Package mcpcontract holds the MCP tool contracts the engine serves: one
// JSON file per tool under tools/, embedded so the engine lists the
// contract's input schema verbatim, and the next-steps catalog under
// errors/. See CONTRACT.md, "Process: contract first" and "Next steps".
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

// Next-step actors (CONTRACT.md, Next steps). ActorOperator is catalog-only:
// a machine step on the engine's machine, which Resolve turns into
// ActorAgent or ActorPerson by the engine's operatedBy. It never goes on the
// wire.
const (
	ActorAgent    = "AGENT"
	ActorPerson   = "PERSON"
	ActorOperator = "OPERATOR"
)

// Who operates the engine's machine: engine.json operatedBy (CONTRACT.md,
// Setup from your laptop).
const (
	OperatedByPerson = "PERSON"
	OperatedByAgent  = "AGENT"
)

// ActionRunCommand is the one action an AGENT step may take only when the
// engine's operatedBy is AGENT, and the only action of an OPERATOR step.
const ActionRunCommand = "RUN_COMMAND"

// ActorActions lists the actions each actor may take in a next step
// (CONTRACT.md, Next steps).
var ActorActions = map[string][]string{
	ActorAgent:    {"CALL_TOOL", "REVISE_CALL", "RETRY_SMALLER_BATCHES", "ASK_PERSON", "END_TURN", "STOP", ActionRunCommand},
	ActorPerson:   {"OPEN_LINK", ActionRunCommand, "TELL_AGENT"},
	ActorOperator: {ActionRunCommand},
}

// Resolve returns steps with every OPERATOR step addressed to the agent when
// operatedBy is AGENT and to the person otherwise (PERSON, or a config the
// shim cannot read).
func Resolve(steps []StepKind, operatedBy string) []StepKind {
	actor := ActorPerson
	if operatedBy == OperatedByAgent {
		actor = ActorAgent
	}
	out := make([]StepKind, len(steps))
	for i, s := range steps {
		if s.Actor == ActorOperator {
			s.Actor = actor
		}
		out[i] = s
	}
	return out
}

//go:embed errors/next-steps.json
var nextStepsFile []byte

// StepKind is one step of a catalog entry: who acts and how. The catalog
// fixes the sequence; the engine fills in text, tool, arguments and commands.
type StepKind struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
}

// ErrorSteps is the catalog entry of one error case: a code, its reason
// (empty for the code's only or default case) and, where a tool's steps
// differ, that tool.
type ErrorSteps struct {
	Code          string     `json:"code"`
	Reason        string     `json:"reason,omitempty"`
	Tool          string     `json:"tool,omitempty"`
	PersonMessage bool       `json:"personMessage"`
	Steps         []StepKind `json:"steps"`
}

// ResultSteps is the catalog entry of a result the agent must act on.
type ResultSteps struct {
	Tool          string     `json:"tool"`
	Case          string     `json:"case"`
	PersonMessage bool       `json:"personMessage"`
	Steps         []StepKind `json:"steps"`
}

// WarningSteps is the catalog entry of a result warning.
type WarningSteps struct {
	Code          string     `json:"code"`
	PersonMessage bool       `json:"personMessage"`
	Steps         []StepKind `json:"steps"`
}

// Problem severities of the status tool (CONTRACT.md, Next steps).
const (
	SeverityError   = "ERROR"
	SeverityWarning = "WARNING"
)

// ProblemSteps is the catalog entry of a problem the status tool reports.
type ProblemSteps struct {
	Code          string     `json:"code"`
	Severity      string     `json:"severity"`
	PersonMessage bool       `json:"personMessage"`
	Steps         []StepKind `json:"steps"`
}

// Kinds of entry an agent-operated variant replaces.
const (
	VariantError   = "ERROR"
	VariantWarning = "WARNING"
	VariantProblem = "PROBLEM"
)

// VariantSteps replaces the steps of one error, warning or status problem
// entry when the engine's operatedBy is AGENT: the person's admin step on
// the engine's machine becomes the agent making a setup code (CONTRACT.md,
// Next steps).
type VariantSteps struct {
	Kind          string     `json:"kind"`
	Code          string     `json:"code"`
	Reason        string     `json:"reason,omitempty"`
	Tool          string     `json:"tool,omitempty"`
	PersonMessage bool       `json:"personMessage"`
	Steps         []StepKind `json:"steps"`
}

// NextSteps is api/mcp/errors/next-steps.json: for every error case, result
// case, warning and status problem, the steps the engine returns, in order,
// and the variants that replace some of them on an agent-operated engine.
type NextSteps struct {
	Errors        []ErrorSteps   `json:"errors"`
	Results       []ResultSteps  `json:"results"`
	Warnings      []WarningSteps `json:"warnings"`
	Problems      []ProblemSteps `json:"problems"`
	AgentOperated []VariantSteps `json:"agentOperated"`
}

// AgentOperatedEntry returns the variant of kind for code, reason and tool
// on an agent-operated engine, if the catalog has one; otherwise the entry's
// own steps apply, resolved with Resolve.
func (c NextSteps) AgentOperatedEntry(kind, code, reason, tool string) (VariantSteps, bool) {
	for _, v := range c.AgentOperated {
		if v.Kind == kind && v.Code == code && v.Reason == reason && v.Tool == tool {
			return v, true
		}
	}
	return VariantSteps{}, false
}

// LoadNextSteps decodes the embedded next-steps catalog strictly.
func LoadNextSteps() (NextSteps, error) {
	var c NextSteps
	dec := json.NewDecoder(strings.NewReader(string(nextStepsFile)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return NextSteps{}, fmt.Errorf("decode errors/next-steps.json: %w", err)
	}
	return c, nil
}

// ErrorEntry returns the entry for code and reason as returned by tool: the
// tool's own entry when it has one, else the entry for every tool.
func (c NextSteps) ErrorEntry(code, reason, tool string) (ErrorSteps, bool) {
	var fallback *ErrorSteps
	for i, e := range c.Errors {
		if e.Code != code || e.Reason != reason {
			continue
		}
		if e.Tool == tool {
			return e, true
		}
		if e.Tool == "" {
			fallback = &c.Errors[i]
		}
	}
	if fallback == nil {
		return ErrorSteps{}, false
	}
	return *fallback, true
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
