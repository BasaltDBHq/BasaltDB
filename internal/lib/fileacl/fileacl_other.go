//go:build !linux && !darwin

package fileacl

func opens(string, Grant) (bool, error) { return false, nil }

func clearACL(int) error { return nil }
