package pii

import (
	"io"
	"math"
)

// Files of the dictionary in the engine's stateDir (CONTRACT.md, PII
// classification, engine files).
const (
	DictionaryDirName  = "pii"
	DictionaryFileName = "dictionary.bin"
	StatusFileName     = "status.json"
)

// KeyFileName is k_master's file in the engine's stateDir (decision M51-1).
const KeyFileName = "pii.key"

// maxMapSize is the largest file a slice can address on this platform.
const maxMapSize = math.MaxInt

// DictionaryArrayAlign is the alignment a dictionary file's bytes need in
// memory, for the fingerprint arrays.
const DictionaryArrayAlign = dictArrayAlign

// DictionaryFiles keeps a FuseDictionary's files, dictionary.bin and
// status.json (statefile/dictfile, in <stateDir>/pii). The file checks (no
// link, the engine user's, the modes) are its own.
type DictionaryFiles interface {
	// Prepare creates the files' directory when missing and checks it. It
	// is called once, before the rest.
	Prepare() error
	// BasePath names dictionary.bin in errors.
	BasePath() string
	// MapBase maps dictionary.bin read-only, after checking the file and its
	// size (CheckDictionarySize). found is false when there is no file; err
	// then says so.
	MapBase() (data []byte, unmap func() error, found bool, err error)
	// WriteBase replaces dictionary.bin, whole, with what write writes.
	WriteBase(write func(w io.WriteSeeker) error) error
	// ReadStatus reads status.json back (the last scan survives a restart).
	// Any problem gives a zero status: it only carries counts.
	ReadStatus() DictionaryStatus
	// WriteStatus replaces status.json.
	WriteStatus(st DictionaryStatus) error
}

// CheckDictionarySize refuses a dictionary file too small for its header or
// too large to map. The error is a file whose content is unusable, which
// is rebuilt.
func CheckDictionarySize(size int64) error {
	if size < dictHeaderSize || size > maxMapSize {
		return invalidf("size %d", size)
	}
	return nil
}
