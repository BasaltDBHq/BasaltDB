package guardmodel

import "errors"

// ErrLabelNotListed is a label for a column the agent role may not read, or
// one that has a class: the check never lists it. Nothing is written.
var ErrLabelNotListed = errors.New("a label for a column the check does not list")

// AgentColumn is a column the agent role may read, with its class now.
type AgentColumn struct {
	ReadableColumn
	Label
}

// TableName is schema.table.
func (c AgentColumn) TableName() string { return c.Schema + "." + c.Table }
