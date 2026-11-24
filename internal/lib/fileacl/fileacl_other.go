//go:build !linux && !darwin

package fileacl

func opens(string, Grant) (bool, error) { return false, nil }
