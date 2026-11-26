// Package piistore holds the types the PII domain's store ports are written
// in: a field's class, the marks a class map is loaded with, the fields the
// hourly check reports, and the fields of a result the agent is about to
// get, in words that fit any store. Fields and resources are the agent's
// opaque refs (action.FieldRef, action.ResourceRef). The store's
// adapter fills them; internal/pii decides what to do with them. Types only.
//
// The classifier's side: Kind (how a field's values are treated), Column (a
// field as setup lists it, by its printed names, never by ref) and Sample
// (the values read from it). The dictionary scan's side: ScanTarget (one
// resource's IDENTIFIER fields) and the two errors that skip a resource,
// ErrUnreadable and ErrTooSlow.
package piistore
