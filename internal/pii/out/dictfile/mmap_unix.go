//go:build unix

package dictfile

import (
	"os"

	"golang.org/x/sys/unix"
)

// mapFile maps size bytes of f read-only. The mapping outlives f; unmap
// releases it. The engine only ever replaces the file by a rename, never
// truncates it in place. With MAP_SHARED, another process running as the
// engine's user that truncates the mapped file makes the next lookup on a
// lost page raise SIGBUS and crash the engine. That is outside the threat
// model: that user can already change the key and the engine's binary.
// Lookups do not use debug.SetPanicOnFault: it would add a deferred recover to
// each lookup (about 55 ns now), and a recovered fault would still have to
// fail the request closed, which the crash already does.
func mapFile(f *os.File, size int) ([]byte, func() error, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return unix.Munmap(data) }, nil
}
