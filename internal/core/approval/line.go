package approval

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/textrule"
)

// Row operations in a preview line.
const (
	OpInsert = "INSERT"
	OpUpdate = "UPDATE"
	OpDelete = "DELETE"
)

// Shapes: which kind of data a line's values describe (CONTRACT.md,
// Stores, Shapes). A page draws RECORD and refuses to offer signing for
// OBJECT, which is reserved, or any other shape.
const (
	ShapeRecord = "RECORD"
	ShapeObject = "OBJECT"
)

// knownShape reports a shape the contract names.
func knownShape(s string) bool {
	return s == ShapeRecord || s == ShapeObject
}

// LineStore is a preview line's store part: the store's kind and its own
// word for the row's operation.
type LineStore struct {
	Kind string `json:"kind"`
	Verb string `json:"verb"`
}

// Line is one parsed preview line (CONTRACT.md, Approvals). Key, Old and Set
// keep the person's field names and values exactly as the store returned
// them. A redacted line has only Op, Shape, Store, Resource, RowHash and
// Cascaded.
type Line struct {
	Op       string          `json:"op"`
	Key      json.RawMessage `json:"key,omitempty"`
	Old      json.RawMessage `json:"old,omitempty"`
	Set      json.RawMessage `json:"set,omitempty"`
	Shape    string          `json:"shape"`
	Store    LineStore       `json:"store"`
	Resource string          `json:"resource"`
	Cascaded bool            `json:"cascaded"`
	Redacted bool            `json:"redacted,omitempty"`
	RowHash  string          `json:"rowHash,omitempty"`
}

// ParseLine parses one preview line for display: the text rules, then its
// keys, op, shape, store part and resource.
func ParseLine(text string) (Line, error) {
	if err := textrule.Check(text); err != nil {
		return Line{}, Invalid("preview line: %v", err)
	}
	var l Line
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Line{}, Invalid("preview line: %v", err)
	}
	switch l.Op {
	case OpInsert, OpUpdate, OpDelete:
	default:
		return Line{}, Invalid("preview line op %q", l.Op)
	}
	if err := CheckLinePart(l.Shape, l.Store.Kind, l.Store.Verb, l.Resource); err != nil {
		return Line{}, Invalid("preview line %v", err)
	}
	return l, nil
}

// CheckLinePart checks what every line carries whatever its kind: a shape
// the contract names, a store kind and verb, and a resource.
func CheckLinePart(shape, kind, verb, resource string) error {
	switch {
	case !knownShape(shape):
		return Invalid("shape %q", shape)
	case !storeKind.MatchString(kind) || verb == "":
		return Invalid("store needs a kind and a verb")
	case resource == "":
		return Invalid("without a resource")
	}
	return nil
}

// AgentPrefix starts an agent's name in every text (CONTRACT.md, Stores,
// Agent names): agent:<name>, never the store's login for it.
const AgentPrefix = "agent:"

// maxAgentText is the longest agent:<name>: the prefix and a name of at most
// 63 characters.
const maxAgentText = 69

var agentText = regexp.MustCompile(`^agent:[a-z][a-z0-9_]*$`)

// IsAgentName reports whether s is agent:<name>.
func IsAgentName(s string) bool {
	return len(s) <= maxAgentText && agentText.MatchString(s)
}

// AgentName is the agent named name as every text names it: agent:<name>.
func AgentName(name string) string {
	return AgentPrefix + name
}

// AgentShown is the agent's name as a page or a message shows it: the name
// without agent:.
func AgentShown(text string) string {
	return strings.TrimPrefix(text, AgentPrefix)
}
