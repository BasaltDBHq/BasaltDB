// Package pii suggests a PII class for every column the agents can read
// (CONTRACT.md, PII classification; M5.1 plan, section 3): name rules, then
// validators over a bounded sample of the column's values, then the shape of
// numeric columns. Values stay in memory and are dropped after scoring:
// suggestions and reasons carry names and counts, never a value.
//
// It also keeps the engine's PII dictionary fresh (M5.1 plan, section 6):
// the classification map of the columns an agent reads, the values the agent
// reads added before they leave the engine, the throttled scan that rebuilds
// the dictionary, and the hourly classification check. Nothing here logs,
// returns or stores a value in plain form: logs carry column names and counts
// only.
package pii
