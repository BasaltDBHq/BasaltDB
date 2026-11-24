package statuscli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/status"
)

func TestPrintUpdateLine(t *testing.T) {
	n := &status.UpdateNotice{Line: "basalt 0.0.1 is out of date; 0.0.2 is available."}
	var b bytes.Buffer
	PrintUpdateLine(&b, func(string) string { return "" }, n)
	if got := b.String(); strings.Contains(got, "\x1b") || !strings.Contains(got, "basalt 0.0.1 is out of date; 0.0.2 is available.") || !strings.HasSuffix(got, "\n") {
		t.Errorf("non-terminal output = %q", got)
	}
	b.Reset()
	PrintUpdateLine(&b, func(string) string { return "" }, nil)
	if b.Len() != 0 {
		t.Errorf("printed without a notice: %q", b.String())
	}
}
