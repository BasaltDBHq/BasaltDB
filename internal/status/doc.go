// Package status is the engine's status use case: the status tool's report
// for an agent, the admission of each tool call against the guard and the
// pending setup, and the warnings that come from the guard's state. It also
// holds the engine's daily check of the hosted portal
// (CONTRACT.md, CLI, `basalt portal verify`; Next steps, PORTAL_MISMATCH).
// Once a day the engine runs the same comparison as `basalt portal verify`
// against the portal in its config and keeps the answer: in memory for the
// status tool, and in a file in the state directory for `basalt status` on
// an engine that runs as the person. The check reads public pages only and
// sends nothing about the engine. It never stops the engine and never blocks
// a tool: a portal that differs is a warning, not a refusal.
//
// The comparison (verify.go) checks the files the hosted portal serves
// against the copy of the pages embedded in the basalt binary. It reads over
// HTTPS (or a loopback test server) and needs no database and no engine. It
// catches a portal that changed broadly; it cannot catch one that serves a
// different page to one person.
package status
