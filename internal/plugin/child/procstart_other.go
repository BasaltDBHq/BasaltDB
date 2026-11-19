//go:build !linux && !darwin

package child

// procStart is unknown here: no process is ever recorded, so none is
// killed by Reap.
func procStart(int) (string, error) { return "", errNoStart }
