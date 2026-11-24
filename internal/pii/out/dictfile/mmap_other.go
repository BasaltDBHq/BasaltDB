//go:build !unix

package dictfile

import (
	"io"
	"os"
	"unsafe"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

// mapFile reads the file into memory outside Unix, into a buffer aligned for
// the fingerprint arrays. unmap is a no-op: the garbage collector frees it.
func mapFile(f *os.File, size int) ([]byte, func() error, error) {
	words := make([]uint64, (size+pii.DictionaryArrayAlign-1)/pii.DictionaryArrayAlign)
	data := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(words))), size)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, nil, err
	}
	return data, func() error { return nil }, nil
}
