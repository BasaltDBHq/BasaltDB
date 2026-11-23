// Package pii suggests a PII class for every column the agents can read
// (CONTRACT.md, PII classification; M5.1 plan, section 3): name rules, then
// validators over a bounded sample of the column's values, then the shape of
// numeric columns. Values stay in memory and are dropped after scoring:
// suggestions and reasons carry names and counts, never a value.
package pii
