//go:build unix

package pii

import (
	"os"

	"golang.org/x/sys/unix"
)

// mapFile maps size bytes of f read-only. The mapping outlives f; unmap
// releases it. The file is only ever replaced by a rename, never truncated in
// place, so a mapped page cannot vanish under a lookup.
func mapFile(f *os.File, size int) ([]byte, func() error, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return unix.Munmap(data) }, nil
}
