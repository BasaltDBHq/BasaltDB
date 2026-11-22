//go:build !linux && !darwin

package peercred

func peerUID(int) (uint32, error) {
	return 0, ErrUnsupported
}
