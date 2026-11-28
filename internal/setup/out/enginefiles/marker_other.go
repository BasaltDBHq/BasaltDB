//go:build !unix

package enginefiles

import "errors"

// CreateMarker: the removal job runs on macOS and Linux only.
func (Files) CreateMarker(string) error {
	return errors.New("the removal job runs on macOS and Linux only")
}
