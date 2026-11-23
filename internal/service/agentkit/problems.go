package agentkit

import (
	"cmp"
	"fmt"
	"slices"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// Problem is one entry of status.problems.
type Problem struct {
	Code          string `json:"code"`
	Severity      string `json:"severity"`
	Message       string `json:"message"`
	PersonMessage string `json:"personMessage,omitempty"`
	// Links are the URLs of PersonMessage, with labels (present exactly when
	// it holds a URL).
	Links     []toolresult.Link     `json:"links,omitempty"`
	NextSteps []toolresult.NextStep `json:"nextSteps"`
}

// Problems collects status problems, each built from its catalog entry.
type Problems struct {
	Cmds Commands
	// ConnectBudget: see Deps.ConnectBudget.
	ConnectBudget int
	list          []Problem
	err           error
}

// Add builds the problem code with the steps steps returns along with the
// person's message.
func (ps *Problems) Add(code, message string, steps func(*Steps) string) {
	ps.AddLinked(code, message, func(b *Steps) (string, []toolresult.Link) { return steps(b), nil })
}

// AddLinked is Add for a message that carries links.
func (ps *Problems) AddLinked(code, message string, steps func(*Steps) (string, []toolresult.Link)) {
	entry, ok := ProblemEntry(code)
	if !ok {
		ps.Fail(fmt.Errorf("no catalog entry for status problem %s", code))
		return
	}
	b := NewSteps()
	person, ls := steps(b)
	list, err := b.Build()
	if err != nil {
		ps.Fail(fmt.Errorf("status problem %s: %w", code, err))
		return
	}
	person = FitToSteps(person, list)
	if err := CheckPersonMessage(person); err != nil {
		ps.Fail(fmt.Errorf("status problem %s: %w", code, err))
		return
	}
	ps.list = append(ps.list, Problem{Code: code, Severity: entry.Severity, Message: message, PersonMessage: person, Links: ls, NextSteps: list})
}

// Fail records err unless a problem failed before.
func (ps *Problems) Fail(err error) {
	if ps.err == nil {
		ps.err = err
	}
}

// Sorted is the problems, errors first, or the first that could not be built.
func (ps *Problems) Sorted() ([]Problem, error) {
	if ps.err != nil {
		return nil, ps.err
	}
	out := append([]Problem{}, ps.list...)
	slices.SortStableFunc(out, func(a, b Problem) int {
		return cmp.Compare(SeverityRank(a.Severity), SeverityRank(b.Severity))
	})
	return out, nil
}

// SeverityRank orders severities: errors first.
func SeverityRank(s string) int {
	if s == mcpcontract.SeverityError {
		return 0
	}
	return 1
}

// ProblemEntry is the catalog entry of the status problem code.
func ProblemEntry(code string) (mcpcontract.ProblemSteps, bool) {
	for _, p := range Catalog().Problems {
		if p.Code == code {
			return p, true
		}
	}
	return mcpcontract.ProblemSteps{}, false
}
