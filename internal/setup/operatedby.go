package setup

import (
	"fmt"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// OperatedBy is the value of --operated-by: who runs the machine steps on
// this engine's machine. CLI input spelling only; engine.json holds the
// enum (mcpcontract.OperatedByPerson or OperatedByAgent).
type OperatedBy string

// --operated-by values.
const (
	OperatedByPerson OperatedBy = "person"
	OperatedByAgent  OperatedBy = "agent"
)

// String implements flag.Value.
func (o *OperatedBy) String() string { return string(*o) }

// Set implements flag.Value, refusing anything but the two values.
func (o *OperatedBy) Set(v string) error {
	switch OperatedBy(v) {
	case OperatedByPerson, OperatedByAgent:
		*o = OperatedBy(v)
		return nil
	}
	return fmt.Errorf("must be %s or %s", OperatedByPerson, OperatedByAgent)
}

// Enum is the value engine.json stores.
func (o OperatedBy) Enum() string {
	if o == OperatedByAgent {
		return mcpcontract.OperatedByAgent
	}
	return mcpcontract.OperatedByPerson
}
