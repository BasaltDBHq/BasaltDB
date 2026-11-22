package pii

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Dictionary defaults (M5.1 plan, section 5; CONTRACT.md engine config).
const (
	DefaultMaxMemoryMB     = 512
	DefaultMaxDeltaEntries = 1_000_000
	bytesPerMB             = 1 << 20
	// deltaHardLimitFactor: the delta keeps taking values past
	// MaxDeltaEntries, while the early rebuild runs, up to this many times it.
	deltaHardLimitFactor = 2
)

var (
	// ErrDictionaryOverBudget: even 16-bit fingerprints would not fit the
	// memory budget. The previous base and every delta value are kept.
	ErrDictionaryOverBudget = errors.New("pii: dictionary does not fit the memory budget (pii.maxMemoryMB), even with 16-bit fingerprints")
	// ErrDeltaFull: the delta reached its hard limit before a rebuild emptied
	// it. The value was not added; the caller must not return it (fail closed).
	ErrDeltaFull = errors.New("pii: dictionary delta is full; waiting for the rebuild")
	// ErrBuildRunning: one build at a time.
	ErrBuildRunning = errors.New("pii: a dictionary build is already running")
	// ErrBuildDone: a build is committed or aborted once.
	ErrBuildDone = errors.New("pii: dictionary build already finished")
)

// DictionaryOptions sizes the dictionary.
type DictionaryOptions struct {
	// MaxMemoryBytes is the budget for the base filters (pii.maxMemoryMB).
	MaxMemoryBytes int64
	// MaxDeltaEntries starts an early rebuild when the delta reaches it.
	MaxDeltaEntries int
	// Now stamps status.json.
	Now func() time.Time
}

// DefaultDictionaryOptions are the contract defaults; now is the clock that stamps status.json.
func DefaultDictionaryOptions(now func() time.Time) DictionaryOptions {
	return DictionaryOptions{
		MaxMemoryBytes:  DefaultMaxMemoryMB * bytesPerMB,
		MaxDeltaEntries: DefaultMaxDeltaEntries,
		Now:             now,
	}
}

func (o DictionaryOptions) validate() error {
	if o.MaxMemoryBytes <= 0 || o.MaxDeltaEntries <= 0 || o.Now == nil {
		return fmt.Errorf("pii: dictionary options need a positive memory budget, a positive delta cap and a clock")
	}
	return nil
}

// ScanStats describes the scan a build was made from, for status.json.
type ScanStats struct {
	At      time.Time
	Columns int
	Rows    int64
}

// DictionaryStatus is <stateDir>/pii/status.json: counts and times only. The
// value counts are of generic forms, so a two-word PERSON_NAME, stored both
// ways (Keys.GenericHashes), counts twice.
type DictionaryStatus struct {
	DictionaryValues uint64     `json:"dictionaryValues"`
	DeltaValues      int        `json:"deltaValues"`
	FingerprintBits  int        `json:"fingerprintBits"`
	LastScanAt       *time.Time `json:"lastScanAt,omitempty"`
	LastScanColumns  int        `json:"lastScanColumns"`
	LastScanRows     int64      `json:"lastScanRows"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

// FuseDictionary is the engine's dictionary (decision M51-7): a base of binary
// fuse filters, memory-mapped from <stateDir>/pii/dictionary.bin, and an exact
// delta of values added since the last build. It holds keyed hashes and their
// fingerprints only, never a value. A value added to it is always found (no
// false negatives); an unknown hash is found about once in 2^32 lookups per
// filter (2^16 with the 16-bit fallback), which only tokenizes a harmless
// phrase. Safe for concurrent use: lookups take no lock on the base.
type FuseDictionary struct {
	files   DictionaryFiles
	keys    *Keys
	opts    DictionaryOptions
	base    atomic.Pointer[baseFilter]
	rebuild chan struct{}

	mu       sync.RWMutex // guards the delta generations, building and lastScan
	active   *delta       // values added since the last build started
	frozen   *delta       // values added before the running build started
	building bool
	lastScan DictionaryStatus

	discarded error // why the file at open was not used, or nil
}

var _ Dictionary = (*FuseDictionary)(nil)

// OpenDictionary opens the dictionary kept in files (statefile/dictfile's
// Open: <stateDir>/pii). A missing dictionary file, or one that is
// truncated, corrupt, of another format or built with other keys, gives an
// empty base: NeedsBuild then reports true and Discarded why. Any other
// error of files is an error.
func OpenDictionary(files DictionaryFiles, keys *Keys, opts DictionaryOptions) (*FuseDictionary, error) {
	if keys == nil {
		panic("pii.OpenDictionary: keys required")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if err := files.Prepare(); err != nil {
		return nil, err
	}
	d := &FuseDictionary{
		files: files, keys: keys, opts: opts,
		rebuild: make(chan struct{}, 1),
		active:  newDelta(), frozen: newDelta(),
		lastScan: files.ReadStatus(),
	}
	b, found, err := d.openBase()
	switch {
	case err == nil:
		d.base.Store(b)
	case !found:
		d.base.Store(emptyBase())
	case errors.Is(err, errDictionaryInvalid):
		d.base.Store(emptyBase())
		d.discarded = err
	default:
		return nil, err
	}
	return d, nil
}

// openBase maps the dictionary file and parses it. found is false when
// there is no file. Content that is unusable wraps errDictionaryInvalid.
func (d *FuseDictionary) openBase() (*baseFilter, bool, error) {
	data, unmap, found, err := d.files.MapBase()
	if err != nil {
		return nil, found, err
	}
	b, err := parseDictionary(data, d.keys.dictionaryCheck())
	if err != nil {
		_ = unmap()
		return nil, true, fmt.Errorf("pii dictionary %s: %w", d.files.BasePath(), err)
	}
	return newMappedBase(b, unmap), true, nil
}

// NeedsBuild reports whether no base was loaded from disk at open (missing or
// discarded) and no build has been committed since.
func (d *FuseDictionary) NeedsBuild() bool { return d.base.Load().unmap == nil }

// Discarded is why the file found at open was not used (corrupt, truncated,
// another format or key), or nil. It names no value.
func (d *FuseDictionary) Discarded() error { return d.discarded }

// RebuildNeeded receives when the delta reaches MaxDeltaEntries: the engine
// starts a build early.
func (d *FuseDictionary) RebuildNeeded() <-chan struct{} { return d.rebuild }

// FingerprintBits is the width of the current base: 32, or 16 under the
// memory budget.
func (d *FuseDictionary) FingerprintBits() int { return d.base.Load().bits }

// Add puts a value of type t in the delta: its generic and typed hashes, so
// both Lookup and Contains find it from now on. phoneRegion normalizes a
// phone written without +cc. It fails only with ErrDeltaFull or an unknown
// type; then the value is not known and the caller fails closed.
func (d *FuseDictionary) Add(t EntityType, value, phoneRegion string) error {
	ti, ok := typeIndex(t)
	if !ok {
		return fmt.Errorf("pii: unknown entity type %q", t)
	}
	gs, ty := d.keys.GenericHashes(t, value), d.keys.TypedHash(t, value, phoneRegion)
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.deltaSizeLocked()
	if n >= d.opts.MaxDeltaEntries*deltaHardLimitFactor {
		d.signalRebuild()
		return ErrDeltaFull
	}
	d.active.add(ti, gs, ty)
	if n+len(gs) >= d.opts.MaxDeltaEntries {
		d.signalRebuild()
	}
	return nil
}

func (d *FuseDictionary) deltaSizeLocked() int { return d.active.size() + d.frozen.size() }

func (d *FuseDictionary) signalRebuild() {
	select {
	case d.rebuild <- struct{}{}:
	default: // one signal is pending already
	}
}

// Lookup finds a generic-form hash: the delta first, then the base.
func (d *FuseDictionary) Lookup(h Hash) (EntityType, bool) {
	d.mu.RLock()
	m := d.active.generic[h] | d.frozen.generic[h]
	d.mu.RUnlock()
	if t, ok := m.first(); ok {
		return t, true
	}
	b := d.acquireBase()
	defer b.release()
	return b.lookup(h)
}

// Contains reports whether a typed-form hash is known for t: the delta first,
// then the base.
func (d *FuseDictionary) Contains(t EntityType, h Hash) bool {
	ti, ok := typeIndex(t)
	if !ok {
		return false
	}
	d.mu.RLock()
	m := d.active.typed[h] | d.frozen.typed[h]
	d.mu.RUnlock()
	if m.has(ti) {
		return true
	}
	b := d.acquireBase()
	defer b.release()
	return b.contains(ti, h)
}

// acquireBase takes a reference on the current base. A base released between
// the load and the reference was already replaced, so the load is retried.
func (d *FuseDictionary) acquireBase() *baseFilter {
	for {
		b := d.base.Load()
		if b.tryAcquire() {
			return b
		}
	}
}

// Status is what status.json holds now.
func (d *FuseDictionary) Status() DictionaryStatus {
	d.mu.RLock()
	st := d.lastScan
	st.DeltaValues = d.deltaSizeLocked()
	d.mu.RUnlock()
	b := d.acquireBase()
	st.DictionaryValues = b.values
	st.FingerprintBits = b.bits
	b.release()
	st.UpdatedAt = d.opts.Now().UTC()
	return st
}

// WriteStatus writes <stateDir>/pii/status.json (0644) from Status.
func (d *FuseDictionary) WriteStatus() error {
	return d.files.WriteStatus(d.Status())
}

// Close releases the base mapping once no lookup holds it. Lookups after
// Close still see the delta, and an empty base.
func (d *FuseDictionary) Close() error {
	d.base.Swap(emptyBase()).release()
	return nil
}

// StartBuild begins a full build. Values added from now on go to a new delta
// generation that the build leaves in place; the ones added before stay
// visible until the build is committed, then drop out unless the build added
// them again (M51-8). Call it before the scan reads its first row, so a value
// added while the scan runs is never dropped. One build runs at a time.
func (d *FuseDictionary) StartBuild() (*DictionaryBuild, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.building {
		return nil, ErrBuildRunning
	}
	d.building = true
	d.frozen, d.active = d.active, newDelta()
	n := filterCount()
	return &DictionaryBuild{d: d, generic: make([][]uint64, n), typed: make([][]uint64, n)}, nil
}

// DictionaryBuild collects the values of one full scan. It holds their keyed
// hashes (8 bytes each), never the values; the filters are built one shard at
// a time on Commit. Safe for concurrent use.
type DictionaryBuild struct {
	d       *FuseDictionary
	mu      sync.Mutex
	generic [][]uint64 // per filter: generic-form hashes
	typed   [][]uint64 // per filter: typed-form hashes
	done    bool
}

// Add puts a value of type t in the build.
func (b *DictionaryBuild) Add(t EntityType, value, phoneRegion string) error {
	ti, ok := typeIndex(t)
	if !ok {
		return fmt.Errorf("pii: unknown entity type %q", t)
	}
	gs, ty := b.d.keys.GenericHashes(t, value), b.d.keys.TypedHash(t, value, phoneRegion)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return ErrBuildDone
	}
	for _, g := range gs {
		gi := filterIndex(ti, g)
		b.generic[gi] = append(b.generic[gi], uint64(g))
	}
	tyi := filterIndex(ti, ty)
	b.typed[tyi] = append(b.typed[tyi], uint64(ty))
	return nil
}

// Commit builds the filters (32-bit fingerprints, or 16-bit when 32 would
// exceed the memory budget), writes them to a temp file renamed over
// dictionary.bin, maps the new file, writes status.json and swaps the new
// base in. The old mapping is released when no lookup holds it. On any error
// nothing was swapped: the previous base and every delta value stay
// (ErrDictionaryOverBudget when even 16 bits would not fit).
func (b *DictionaryBuild) Commit(scan ScanStats) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return ErrBuildDone
	}
	b.done = true
	keys, values := b.mergeKeys()
	b.generic, b.typed = nil, nil
	nb, err := b.d.writeBase(keys, values)
	if err != nil {
		b.d.endBuild(false, ScanStats{})
		return err
	}
	// status.json is written before the swap, so an error here means the
	// commit failed: the old base and every delta value stay.
	if err := b.d.files.WriteStatus(b.d.statusAfterBuild(nb, scan)); err != nil {
		nb.release()
		b.d.endBuild(false, ScanStats{})
		return fmt.Errorf("pii: write %s: %w", StatusFileName, err)
	}
	b.d.base.Swap(nb).release()
	b.d.endBuild(true, scan)
	return nil
}

// statusAfterBuild is the status once nb is swapped in and the frozen delta
// dropped.
func (d *FuseDictionary) statusAfterBuild(nb *baseFilter, scan ScanStats) DictionaryStatus {
	d.mu.RLock()
	st := withScan(d.lastScan, scan)
	st.DeltaValues = d.active.size()
	d.mu.RUnlock()
	st.DictionaryValues = nb.values
	st.FingerprintBits = nb.bits
	st.UpdatedAt = d.opts.Now().UTC()
	return st
}

// withScan is st with the last scan set to scan (an unset time keeps the
// previous one).
func withScan(st DictionaryStatus, scan ScanStats) DictionaryStatus {
	if !scan.At.IsZero() {
		at := scan.At.UTC()
		st.LastScanAt = &at
	}
	st.LastScanColumns = scan.Columns
	st.LastScanRows = scan.Rows
	return st
}

// Abort ends the build without changing the base; every delta value stays.
func (b *DictionaryBuild) Abort() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return
	}
	b.done = true
	b.generic, b.typed = nil, nil
	b.d.endBuild(false, ScanStats{})
}

// mergeKeys returns each filter's distinct keys (generic and typed forms) and
// the number of distinct generic forms per entity type (DictionaryStatus).
func (b *DictionaryBuild) mergeKeys() ([][]uint64, uint64) {
	keys := make([][]uint64, len(b.generic))
	var values uint64
	for i := range b.generic {
		g := sortedUnique(b.generic[i])
		values += uint64(len(g))
		keys[i] = sortedUnique(append(g, b.typed[i]...))
	}
	return keys, values
}

func sortedUnique(s []uint64) []uint64 {
	slices.Sort(s)
	return slices.Compact(s)
}

// writeBase sizes the build against the budget, writes the file and maps it.
func (d *FuseDictionary) writeBase(keys [][]uint64, values uint64) (*baseFilter, error) {
	counts := make([]int, len(keys))
	for i, k := range keys {
		counts[i] = len(k)
	}
	fpBits, err := chooseFingerprintBits(counts, d.opts.MaxMemoryBytes)
	if err != nil {
		return nil, err
	}
	err = d.files.WriteBase(func(w io.WriteSeeker) error {
		return writeDictionary(w, keys, fpBits, values, d.keys.dictionaryCheck())
	})
	if err != nil {
		return nil, fmt.Errorf("pii: write dictionary %s: %w", d.files.BasePath(), err)
	}
	b, _, err := d.openBase()
	return b, err
}

// chooseFingerprintBits is 32 when that file fits the budget, else 16 when
// that fits, else ErrDictionaryOverBudget: precision drops before coverage.
func chooseFingerprintBits(counts []int, budget int64) (int, error) {
	for _, fpBits := range []int{FingerprintBits32, FingerprintBits16} {
		if dictionaryFileSize(counts, fpBits) <= uint64(budget) {
			return fpBits, nil
		}
	}
	return 0, ErrDictionaryOverBudget
}

// endBuild drops the frozen delta after a committed build, or merges it back
// into the active one when the build failed, so no added value is lost.
func (d *FuseDictionary) endBuild(committed bool, scan ScanStats) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.building = false
	if !committed {
		d.active.merge(d.frozen)
		d.frozen = newDelta()
		if d.active.size() >= d.opts.MaxDeltaEntries {
			d.signalRebuild()
		}
		return
	}
	d.frozen = newDelta()
	d.lastScan = withScan(d.lastScan, scan)
}

func filterIndex(ti int, h Hash) int { return ti*dictShardCount + int(h>>dictShardShift) }

func typeIndex(t EntityType) (int, bool) {
	i := slices.Index(entityTypes, t)
	return i, i >= 0
}

// typeMask is a set of entity types, bit i for entityTypes[i].
type typeMask uint8

func (m typeMask) has(ti int) bool { return m&(1<<ti) != 0 }

// first is the first type in the set, in contract order.
func (m typeMask) first() (EntityType, bool) {
	for i, t := range entityTypes {
		if m.has(i) {
			return t, true
		}
	}
	return "", false
}

// delta is an exact set of hashes with the types they were added as.
type delta struct {
	generic map[Hash]typeMask
	typed   map[Hash]typeMask
}

func newDelta() *delta {
	return &delta{generic: map[Hash]typeMask{}, typed: map[Hash]typeMask{}}
}

func (dl *delta) add(ti int, gs []Hash, ty Hash) {
	for _, g := range gs {
		dl.generic[g] |= 1 << ti
	}
	dl.typed[ty] |= 1 << ti
}

// size counts generic forms: one per value, two for a two-word name.
func (dl *delta) size() int { return len(dl.generic) }

func (dl *delta) merge(o *delta) {
	for h, m := range o.generic {
		dl.generic[h] |= m
	}
	for h, m := range o.typed {
		dl.typed[h] |= m
	}
}
