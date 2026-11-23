// Package agent is what the engine does for one agent: the tool services
// (policy check, then one statement on the agent's scoped credential,
// writes through the guard) and the MCP tools that front them, built from
// the contracts in api/mcp.
//
// The files are grouped by use case, and the file name prefix says which:
//
//   - write_: the write tool and the hold path that a held write follows.
//   - approval_: held writes and plugin approvals, the pending list, and the
//     approval pages the person opens.
//   - revert_: the revert tools, the person's revert pages, rescoping and
//     rejecting a revert, and the next steps they return.
//   - delivery_: getting a link or a notice to the person (links, relays,
//     receipts, large requests) and the answers the pages give back.
//   - status_: the status tool, the guard and setup checks behind it, and
//     the problems it reports.
//   - describe_: the describe tool; the use case and the catalog it reads are internal/agent.
//   - plugin_: the plugin request tool.
//
// service.go holds the shared Service and its dependencies, tools.go and
// tools_runs.go register the tools, and kit.go, host.go, meta.go and
// exact_json.go hold the types and helpers every use case shares.
package agent
