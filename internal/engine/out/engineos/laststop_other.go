//go:build !unix

package engineos

import "github.com/basaltdbhq/basaltdb/internal/core/guidance"

// ReadLastStop reads nothing where the supervisor does not run: it has no
// record to show.
func (OS) ReadLastStop(string) (guidance.LastStop, bool) { return guidance.LastStop{}, false }
