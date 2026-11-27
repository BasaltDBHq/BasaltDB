package pgstatement_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgstatement"
)

// TestMain parses one statement before any test runs. The first parse in a
// process compiles the wasm parser, which takes seconds under -race; done
// here once, it is not billed to whichever parallel tests happen to start
// first, and a broken parser fails the package up front.
func TestMain(m *testing.M) {
	if _, err := pgstatement.Check("SELECT 1", pgstatement.ToolQuery); err != nil {
		fmt.Fprintln(os.Stderr, "pgstatement: warming the parser failed:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
