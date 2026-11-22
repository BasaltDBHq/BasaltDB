// Package guardmodel is the guard's vocabulary: the role names of an
// install, the agent spec, PII classes and column labels, the guard's error
// codes and refusal details, the guard status, revert scopes and results,
// plugin events, approvals and settings, and setup kinds. It holds types,
// constants and pure checks only; the SQL that installs and calls the guard
// stays in internal/adapter/outbound/postgres/guard.
package guardmodel
