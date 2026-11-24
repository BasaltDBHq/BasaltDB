package sqlguard_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// TestMain parses one statement before any test runs. The first parse in a
// process compiles the wasm parser, which takes seconds under -race; done
// here once, it is not billed to whichever parallel tests happen to start
// first, and a broken parser fails the package up front.
func TestMain(m *testing.M) {
	if _, err := sqlguard.Check("SELECT 1", sqlguard.ToolQuery); err != nil {
		fmt.Fprintln(os.Stderr, "sqlguard: warming the parser failed:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
