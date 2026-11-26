// Package guardmodel is Basalt's vocabulary that the ledger, the guard and
// the services share: the role names of an install, the agent spec, PII
// classes and column labels, the guard status, revert outcomes and rescope
// paths, the note and hold limits, feed and plugin events, plugin approvals
// and settings, and setup kinds. It holds types, constants and pure checks
// only. The Postgres guard's own error codes and refusal details (SQLSTATE
// class BS, its MESSAGE and DETAIL) live with the guard adapter in
// internal/platform/postgres/guard, which maps them to internal/core/action's
// codes and reasons; the SQL that installs and calls the guard stays there
// too.
package guardmodel
