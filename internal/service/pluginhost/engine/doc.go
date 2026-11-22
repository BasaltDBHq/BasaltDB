// Package engine is the plugin feature of a running engine: it verifies the
// enabled plugin entries, runs them under the host's supervisor, feeds them
// the ledger's events, hands them approval notices, records their entries in
// each agent's ledger, and keeps and approves the entries a service engine
// keeps itself (CONTRACT.md, Plugins).
//
// It reaches the world through ports the app hands over in Options (ports.go):
// the guard's plugin ledger, the transports, the OS units and the network
// rule. The path rule is the host's (pluginhost.PathRules). The app builds
// them and starts the feature; nothing else about plugins lives there.
package engine
