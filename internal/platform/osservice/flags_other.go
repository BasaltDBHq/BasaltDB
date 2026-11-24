//go:build unix && !darwin

package osservice

// clearUserFlags does nothing outside macOS: there an owner cannot make a
// file immutable to root (Linux's immutable attribute needs a capability).
func clearUserFlags(int) error { return nil }
