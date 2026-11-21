package main

import (
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// engineSummary prints the engine lines of the summary (step 5).
func (l *laptopSetup) engineSummary(checked setup.Checked) {
	for _, line := range checked.EngineLines {
		fprintSafef(l.c.stdout, "%s\n", line)
	}
}
