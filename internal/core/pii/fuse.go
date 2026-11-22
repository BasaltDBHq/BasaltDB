package pii

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/bits"
	"sync/atomic"
	"unsafe"

	"github.com/FastFilter/xorfilter"
)

// The dictionary file (<stateDir>/pii/dictionary.bin) holds the base layer:
// one binary fuse filter (Graf and Lemire, 2022) per entity type and shard,
// built by github.com/FastFilter/xorfilter. It holds fingerprints of keyed
// hashes only, never a value. Layout, little endian:
//
//	header      dictHeaderSize bytes (fields at the offsets below)
//	arrays      each shard's fingerprints, in table order, each padded to dictArrayAlign
//	table       one dictShardEntrySize entry per (entity type, shard)
//
// The CRC-32C in the header covers everything after the header, so a flipped
// fingerprint (which could hide a value) is caught before the file is used.
const (
	dictMagic         = "BSLTDICT"
	dictFormatVersion = 1

	// dictShardCount: filters are split by the top byte of the hash, so a
	// build holds the filter of one shard at a time.
	dictShardCount = 256
	dictShardShift = 56

	dictHeaderSize     = 64
	dictShardEntrySize = 32
	dictArrayAlign     = 8

	// Header field offsets.
	hdrFormatVersion = 8
	hdrKeyVersion    = 12
	hdrKeyCheck      = 16
	hdrBits          = 24
	hdrTypeCount     = 28
	hdrShardCount    = 32
	hdrCRC           = 36
	hdrValues        = 40
	hdrFileSize      = 48
	hdrTableOffset   = 56

	// Shard entry field offsets.
	entKeys     = 0
	entSegLen   = 4
	entSegCount = 8
	entSeed     = 16
	entOffset   = 24

	// fuseArity is the number of slots a binary fuse filter reads per lookup.
	fuseArity = 3
	// maxSegmentLength is the library's cap on a segment's length.
	maxSegmentLength = 262144
)

// Fingerprint widths: 32 bits by default (a false positive about once in 4
// billion lookups per filter), 16 when the memory budget needs it.
const (
	FingerprintBits32 = 32
	FingerprintBits16 = 16
)

// bitsPerByte converts fingerprint widths to bytes.
const bitsPerByte = 8

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// errDictionaryInvalid marks a dictionary file whose content cannot be used:
// truncated, corrupt, another format, or built with other keys. Such a file is
// discarded and rebuilt; it is never an error at start.
var errDictionaryInvalid = errors.New("pii: dictionary file is not usable")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errDictionaryInvalid}, args...)...)
}

// hostLittleEndian: the arrays are used in place, so the file is read only on
// a little-endian host (every release target is).
var hostLittleEndian = binary.NativeEndian.Uint16([]byte{1, 0}) == 1

// baseFilter is the immutable base layer: the filters of one dictionary file,
// usually memory-mapped. Lookups take a reference (tryAcquire, release) so the
// mapping is released only when the last lookup is done with it.
type baseFilter struct {
	bits   int
	values uint64
	keys   []uint32 // per filter (entity type index * dictShardCount + shard)
	f32    []xorfilter.BinaryFuse[uint32]
	f16    []xorfilter.BinaryFuse[uint16]
	// unmap releases the mapping; nil for a base that is not mapped.
	unmap func() error
	// refs is 1 for the dictionary's own reference plus one per lookup in flight.
	refs atomic.Int64
}

// emptyBase is the base before any build: it finds nothing.
func emptyBase() *baseFilter { return &baseFilter{bits: FingerprintBits32} }

func newMappedBase(b *baseFilter, unmap func() error) *baseFilter {
	b.unmap = unmap
	b.refs.Store(1)
	return b
}

// tryAcquire takes a reference; false once the mapping is released (the
// caller loads the current base again).
func (b *baseFilter) tryAcquire() bool {
	if b.unmap == nil {
		return true
	}
	for {
		n := b.refs.Load()
		if n <= 0 {
			return false
		}
		if b.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// release drops a reference and unmaps the file when it was the last one.
func (b *baseFilter) release() {
	if b.unmap == nil {
		return
	}
	if b.refs.Add(-1) == 0 {
		// The file stays on disk or was replaced; a failed munmap only leaks
		// address space, and no lookup can reach this base any more.
		_ = b.unmap()
	}
}

// lookup returns the first entity type (contract order) whose filter holds h.
func (b *baseFilter) lookup(h Hash) (EntityType, bool) {
	for i, t := range entityTypes {
		if b.contains(i, h) {
			return t, true
		}
	}
	return "", false
}

// contains reports whether the filter of entity type index ti holds h.
func (b *baseFilter) contains(ti int, h Hash) bool {
	if b.keys == nil {
		return false
	}
	idx := ti*dictShardCount + int(h>>dictShardShift)
	if b.keys[idx] == 0 {
		return false
	}
	if b.bits == FingerprintBits16 {
		return b.f16[idx].Contains(uint64(h))
	}
	return b.f32[idx].Contains(uint64(h))
}

// filterCount is the number of filters in a file: one per entity type and shard.
func filterCount() int { return len(entityTypes) * dictShardCount }

// fuseSlots is the number of fingerprints the library allocates for n keys
// (its initializeParameters, which the halving retry keeps). It sizes a build
// against the memory budget before any filter is built.
func fuseSlots(n int) uint64 {
	if n == 0 {
		return 0
	}
	segLen := uint64(fuseSegmentLength(n))
	capacity := uint64(0)
	if n > 1 {
		capacity = uint64(math.Round(float64(n) * fuseSizeFactor(n)))
	}
	segments := max((capacity+segLen-1)/segLen, fuseArity)
	return segments * segLen
}

// fuseSegmentLength and fuseSizeFactor are the library's empirical formulas
// for arity 3; TestFuseSlotsMatchLibrary keeps them in step with it.
func fuseSegmentLength(n int) uint32 {
	const (
		logBase = 3.33
		offset  = 2.25
	)
	l := uint32(1) << int(math.Floor(math.Log(float64(n))/math.Log(logBase)+offset))
	return min(l, maxSegmentLength)
}

func fuseSizeFactor(n int) float64 {
	const (
		minFactor = 1.125
		base      = 0.875
		weight    = 0.25
		refSize   = 1000000
	)
	return math.Max(minFactor, base+weight*math.Log(refSize)/math.Log(float64(n)))
}

func alignUp(n uint64) uint64 { return (n + dictArrayAlign - 1) &^ (dictArrayAlign - 1) }

// dictionaryFileSize is the size of a dictionary file holding counts[i] keys
// in filter i with fingerprints of the given width.
func dictionaryFileSize(counts []int, fpBits int) uint64 {
	size := uint64(dictHeaderSize)
	for _, n := range counts {
		size += alignUp(fuseSlots(n) * uint64(fpBits/bitsPerByte))
	}
	return size + uint64(len(counts))*dictShardEntrySize
}

type shardEntry struct {
	keys, segLen, segCount uint32
	seed, offset           uint64
}

// writeDictionary builds every filter, one at a time, and writes the file to
// w (positioned at its start). keys[i] holds filter i's distinct keys.
func writeDictionary(w io.WriteSeeker, keys [][]uint64, fpBits int, values, keyCheck uint64) error {
	crc := crc32.New(castagnoli)
	bw := bufio.NewWriter(w)
	if _, err := bw.Write(make([]byte, dictHeaderSize)); err != nil {
		return err
	}
	body := io.MultiWriter(bw, crc)
	entries := make([]shardEntry, len(keys))
	offset := uint64(dictHeaderSize)
	var builder xorfilter.BinaryFuseBuilder
	for i, ks := range keys {
		if len(ks) == 0 {
			continue
		}
		e, n, err := writeFilter(body, &builder, ks, fpBits)
		if err != nil {
			return fmt.Errorf("pii: build dictionary filter %d: %w", i, err)
		}
		e.offset = offset
		entries[i] = e
		offset += n
	}
	tableOffset := offset
	if _, err := body.Write(encodeTable(entries)); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	hdr := encodeHeader(fpBits, values, keyCheck, crc.Sum32(), tableOffset+uint64(len(entries))*dictShardEntrySize, tableOffset)
	if _, err := w.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := w.Write(hdr)
	return err
}

// writeFilter builds one filter and writes its fingerprints, padded; it
// returns the table entry (without offset) and the bytes written.
func writeFilter(w io.Writer, b *xorfilter.BinaryFuseBuilder, ks []uint64, fpBits int) (shardEntry, uint64, error) {
	e, buf, err := encodeFilter[uint32](b, ks)
	if fpBits == FingerprintBits16 {
		e, buf, err = encodeFilter[uint16](b, ks)
	}
	if err != nil {
		return e, 0, err
	}
	e.keys = uint32(len(ks))
	if _, err := w.Write(buf); err != nil {
		return e, 0, err
	}
	return e, uint64(len(buf)), nil
}

// encodeFilter builds a filter with fingerprints of type T and returns its
// parameters and its fingerprints, little endian, padded to dictArrayAlign.
func encodeFilter[T xorfilter.Unsigned](b *xorfilter.BinaryFuseBuilder, ks []uint64) (shardEntry, []byte, error) {
	f, err := xorfilter.BuildBinaryFuse[T](b, ks)
	if err != nil {
		return shardEntry{}, nil, err
	}
	width := int(unsafe.Sizeof(T(0)))
	buf := make([]byte, alignUp(uint64(len(f.Fingerprints)*width)))
	for i, fp := range f.Fingerprints {
		putFingerprint(buf[i*width:], uint32(fp), width)
	}
	return shardEntry{segLen: f.SegmentLength, segCount: f.SegmentCount, seed: f.Seed}, buf, nil
}

func putFingerprint(p []byte, fp uint32, width int) {
	if width == FingerprintBits16/bitsPerByte {
		binary.LittleEndian.PutUint16(p, uint16(fp))
		return
	}
	binary.LittleEndian.PutUint32(p, fp)
}

func encodeTable(entries []shardEntry) []byte {
	out := make([]byte, len(entries)*dictShardEntrySize)
	for i, e := range entries {
		p := out[i*dictShardEntrySize:]
		binary.LittleEndian.PutUint32(p[entKeys:], e.keys)
		binary.LittleEndian.PutUint32(p[entSegLen:], e.segLen)
		binary.LittleEndian.PutUint32(p[entSegCount:], e.segCount)
		binary.LittleEndian.PutUint64(p[entSeed:], e.seed)
		binary.LittleEndian.PutUint64(p[entOffset:], e.offset)
	}
	return out
}

func encodeHeader(fpBits int, values, keyCheck uint64, crc uint32, fileSize, tableOffset uint64) []byte {
	h := make([]byte, dictHeaderSize)
	copy(h, dictMagic)
	binary.LittleEndian.PutUint32(h[hdrFormatVersion:], dictFormatVersion)
	binary.LittleEndian.PutUint32(h[hdrKeyVersion:], KeyVersion)
	binary.LittleEndian.PutUint64(h[hdrKeyCheck:], keyCheck)
	binary.LittleEndian.PutUint32(h[hdrBits:], uint32(fpBits))
	binary.LittleEndian.PutUint32(h[hdrTypeCount:], uint32(len(entityTypes)))
	binary.LittleEndian.PutUint32(h[hdrShardCount:], dictShardCount)
	binary.LittleEndian.PutUint32(h[hdrCRC:], crc)
	binary.LittleEndian.PutUint64(h[hdrValues:], values)
	binary.LittleEndian.PutUint64(h[hdrFileSize:], fileSize)
	binary.LittleEndian.PutUint64(h[hdrTableOffset:], tableOffset)
	return h
}

// parseDictionary checks a whole dictionary file and returns its filters,
// which point into data (data must stay valid while the base is used). Any
// problem is an errDictionaryInvalid; it never panics, whatever data holds.
func parseDictionary(data []byte, keyCheck uint64) (*baseFilter, error) {
	if !hostLittleEndian {
		return nil, invalidf("this host is big-endian")
	}
	if len(data) < dictHeaderSize {
		return nil, invalidf("truncated: %d bytes", len(data))
	}
	if uintptr(unsafe.Pointer(unsafe.SliceData(data)))%dictArrayAlign != 0 { //nolint:gosec // reads the address only, to refuse a misaligned buffer
		return nil, invalidf("buffer not aligned")
	}
	fpBits, tableOffset, err := checkHeader(data, keyCheck)
	if err != nil {
		return nil, err
	}
	if got, want := crc32.Checksum(data[dictHeaderSize:], castagnoli), binary.LittleEndian.Uint32(data[hdrCRC:]); got != want {
		return nil, invalidf("checksum mismatch")
	}
	b := &baseFilter{
		bits:   fpBits,
		values: binary.LittleEndian.Uint64(data[hdrValues:]),
		keys:   make([]uint32, filterCount()),
	}
	if fpBits == FingerprintBits16 {
		b.f16 = make([]xorfilter.BinaryFuse[uint16], filterCount())
	}
	if fpBits == FingerprintBits32 {
		b.f32 = make([]xorfilter.BinaryFuse[uint32], filterCount())
	}
	width := uint64(fpBits / bitsPerByte)
	next := uint64(dictHeaderSize)
	for i := range filterCount() {
		e := decodeEntry(data[tableOffset+uint64(i)*dictShardEntrySize:])
		end, err := checkEntry(e, next, tableOffset, width)
		if err != nil {
			return nil, fmt.Errorf("%w (filter %d)", err, i)
		}
		next = end
		if e.keys == 0 {
			continue
		}
		b.keys[i] = e.keys
		setFilter(b, i, e, data)
	}
	if next != tableOffset {
		return nil, invalidf("arrays end at %d, table starts at %d", next, tableOffset)
	}
	return b, nil
}

// checkHeader checks the header fields and returns the fingerprint width and
// the table offset.
func checkHeader(data []byte, keyCheck uint64) (int, uint64, error) {
	le := binary.LittleEndian
	if string(data[:len(dictMagic)]) != dictMagic {
		return 0, 0, invalidf("not a dictionary file")
	}
	if v := le.Uint32(data[hdrFormatVersion:]); v != dictFormatVersion {
		return 0, 0, invalidf("format version %d, want %d", v, dictFormatVersion)
	}
	if v := le.Uint32(data[hdrKeyVersion:]); v != KeyVersion {
		return 0, 0, invalidf("key version %d, want %d", v, KeyVersion)
	}
	if le.Uint64(data[hdrKeyCheck:]) != keyCheck {
		return 0, 0, invalidf("built with another key")
	}
	fpBits := int(le.Uint32(data[hdrBits:]))
	if fpBits != FingerprintBits16 && fpBits != FingerprintBits32 {
		return 0, 0, invalidf("fingerprint width %d", fpBits)
	}
	if le.Uint32(data[hdrTypeCount:]) != uint32(len(entityTypes)) || le.Uint32(data[hdrShardCount:]) != dictShardCount {
		return 0, 0, invalidf("unexpected filter layout")
	}
	if le.Uint64(data[hdrFileSize:]) != uint64(len(data)) {
		return 0, 0, invalidf("truncated or extended: header says %d bytes, file has %d", le.Uint64(data[hdrFileSize:]), len(data))
	}
	tableOffset := le.Uint64(data[hdrTableOffset:])
	tableSize := uint64(filterCount()) * dictShardEntrySize
	if tableOffset < dictHeaderSize || tableOffset%dictArrayAlign != 0 || tableOffset > uint64(len(data)) || uint64(len(data))-tableOffset != tableSize {
		return 0, 0, invalidf("bad table offset %d", tableOffset)
	}
	return fpBits, tableOffset, nil
}

func decodeEntry(p []byte) shardEntry {
	le := binary.LittleEndian
	return shardEntry{
		keys:     le.Uint32(p[entKeys:]),
		segLen:   le.Uint32(p[entSegLen:]),
		segCount: le.Uint32(p[entSegCount:]),
		seed:     le.Uint64(p[entSeed:]),
		offset:   le.Uint64(p[entOffset:]),
	}
}

// checkEntry checks that a filter's parameters are what the library builds
// (so every slot a lookup computes is inside its array) and that its array
// starts at next and ends before the table. It returns where the next array
// starts.
func checkEntry(e shardEntry, next, tableOffset, width uint64) (uint64, error) {
	if e.keys == 0 {
		if e.segLen != 0 || e.segCount != 0 || e.seed != 0 || e.offset != 0 {
			return 0, invalidf("empty filter with parameters")
		}
		return next, nil
	}
	if e.segLen == 0 || e.segLen > maxSegmentLength || bits.OnesCount32(e.segLen) != 1 {
		return 0, invalidf("segment length %d", e.segLen)
	}
	if e.segCount == 0 {
		return 0, invalidf("no segments")
	}
	// A lookup reads slots below (segCount + arity - 1) * segLen, and the
	// library keeps segCount * segLen in a uint32.
	slots := (uint64(e.segCount) + fuseArity - 1) * uint64(e.segLen)
	if uint64(e.segCount)*uint64(e.segLen) > math.MaxUint32 || uint64(e.keys) > slots {
		return 0, invalidf("filter of %d slots for %d keys", slots, e.keys)
	}
	if e.offset != next {
		return 0, invalidf("array at %d, want %d", e.offset, next)
	}
	end := alignUp(e.offset + slots*width)
	if end > tableOffset {
		return 0, invalidf("array runs into the table")
	}
	return end, nil
}

// setFilter points filter i at its array in data (checked by checkEntry).
func setFilter(b *baseFilter, i int, e shardEntry, data []byte) {
	if b.bits == FingerprintBits16 {
		b.f16[i] = mapFilter[uint16](e, data)
		return
	}
	b.f32[i] = mapFilter[uint32](e, data)
}

// mapFilter is the filter of entry e, its fingerprints read in place from data.
func mapFilter[T xorfilter.Unsigned](e shardEntry, data []byte) xorfilter.BinaryFuse[T] {
	slots := (int(e.segCount) + fuseArity - 1) * int(e.segLen)
	return xorfilter.BinaryFuse[T]{
		Seed:               e.seed,
		SegmentLength:      e.segLen,
		SegmentLengthMask:  e.segLen - 1,
		SegmentCount:       e.segCount,
		SegmentCountLength: e.segCount * e.segLen,
		// Aligned (parseDictionary, alignUp) and inside data (checkEntry).
		Fingerprints: unsafe.Slice((*T)(unsafe.Pointer(&data[e.offset])), slots), //nolint:gosec // aligned and inside data, both checked above
	}
}
