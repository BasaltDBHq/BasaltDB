// Command basalt is the BasaltDB binary: the edge engine, the MCP shim and
// the person's CLI. Milestone M1 adds init, log and the MCP shim; M2 adds
// approve; M3 adds revert. See CONTRACT.md.
package main

import "github.com/basaltdbhq/basaltdb/internal/app"

func main() { app.Main() }
