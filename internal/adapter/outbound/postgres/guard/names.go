// Package guard owns everything BasaltDB installs in the person's Postgres
// (the basalt_meta schema, its roles, triggers and ledger) and the calls
// the engine makes inside an agent's transactions. Agents write only
// through it: every write is recorded in the ledger, held for approval
// when the policy says so, and can be reverted. CONTRACT.md, basalt_meta,
// fixes the objects and their versions.
package guard

import (
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// renderSQL substitutes the validated role names of n into install SQL.
func renderSQL(n guardmodel.Names, sql string) string {
	return strings.NewReplacer("{{guard}}", n.Guard(), "{{agents}}", n.Agents()).Replace(sql)
}
