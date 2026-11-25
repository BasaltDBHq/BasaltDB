// Package piistore holds the types the PII domain's store ports are written
// in: a field's class, the marks a class map is loaded with, the fields the
// hourly check reports, and the fields of a result the agent is about to
// get, in words that fit any store. Fields and resources are the agent's
// opaque refs (agentstore.FieldRef, agentstore.ResourceRef). The store's
// adapter fills them; internal/pii decides what to do with them. Types only.
package piistore
