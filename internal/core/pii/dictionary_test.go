package pii_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/statefile/dictfile"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

var fixedNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func dictOptions() pii.DictionaryOptions {
	o := pii.DefaultDictionaryOptions()
	o.Now = func() time.Time { return fixedNow }
	return o
}

func openDict(t *testing.T, stateDir string, k *pii.Keys, o pii.DictionaryOptions) *pii.FuseDictionary {
	t.Helper()
	d, err := dictfile.Open(stateDir, k, o)
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

type value struct {
	typ    pii.EntityType
	text   string
	region string
}

// buildWith runs a full build of values and commits it.
func buildWith(t *testing.T, d *pii.FuseDictionary, values []value) error {
	t.Helper()
	b, err := d.StartBuild()
	require.NoError(t, err)
	for _, v := range values {
		require.NoError(t, b.Add(v.typ, v.text, v.region))
	}
	return b.Commit(pii.ScanStats{At: fixedNow, Columns: 3, Rows: int64(len(values))})
}

func requireFound(t *testing.T, d pii.Dictionary, k *pii.Keys, v value) {
	t.Helper()
	typ, ok := d.Lookup(k.GenericHash(v.text))
	require.True(t, ok, "generic %s", v.typ)
	require.Equal(t, v.typ, typ)
	require.True(t, d.Contains(v.typ, k.TypedHash(v.typ, v.text, v.region)), "typed %s", v.typ)
}

func requireNotFound(t *testing.T, d pii.Dictionary, k *pii.Keys, v value) {
	t.Helper()
	_, ok := d.Lookup(k.GenericHash(v.text))
	require.False(t, ok)
	require.False(t, d.Contains(v.typ, k.TypedHash(v.typ, v.text, v.region)))
}

// fakeValue is value i of a fixture set: fake names, emails, phones,
// addresses and ids, each distinct.
func fakeValue(i int) value {
	switch i % 5 {
	case 0:
		return value{pii.EntityEmail, fmt.Sprintf("fixture.user%d@example.com", i), ""}
	case 1:
		return value{pii.EntityPhone, fmt.Sprintf("+4477009%05d", i%100000+i/100000), ""}
	case 2:
		return value{pii.EntityPersonName, fmt.Sprintf("Fixture%d Tamm", i), ""}
	case 3:
		return value{pii.EntityAddress, fmt.Sprintf("Pärnu mnt %d, Tallinn", i), ""}
	default:
		return value{pii.EntityOther, fmt.Sprintf("EE%018d", i), ""}
	}
}

// A million values (50,000 unless BASALTDB_TEST_FULL=1) added to a build are all found afterwards, by their
// generic and typed forms, and in other spellings of the same normal form.
func TestDictionaryFindsEveryAddedValue(t *testing.T) {
	n := sized(1_000_000, 50_000)
	k := newKeys(t, testMaster)
	d := openDict(t, t.TempDir(), k, dictOptions())
	values := make([]value, 0, n)
	seen := map[string]bool{}
	for i := range n {
		v := fakeValue(i)
		if v.typ == pii.EntityPhone && seen[v.text] {
			continue
		}
		seen[v.text] = true
		values = append(values, v)
	}
	b, err := d.StartBuild()
	require.NoError(t, err)
	inParallel(len(values), func(i int) {
		v := values[i]
		if err := b.Add(v.typ, v.text, v.region); err != nil {
			t.Errorf("add %d: %v", i, err)
		}
	})
	require.NoError(t, b.Commit(pii.ScanStats{}))
	require.Equal(t, pii.FingerprintBits32, d.FingerprintBits())

	inParallel(len(values), func(i int) {
		v := values[i]
		if !foundAs(d, k, v, v.text) {
			t.Errorf("value %d (%s) not found", i, v.typ)
		}
		if i%100 != 0 {
			return
		}
		// Other spellings normalize to the same forms.
		for _, s := range []string{strings.ToUpper(v.text), "  " + strings.ReplaceAll(v.text, " ", "\u00a0 ") + " ", toFullWidth(v.text)} {
			if !foundAs(d, k, v, s) {
				t.Errorf("a spelling of value %d (%s) not found", i, v.typ)
			}
		}
	})
}

// foundAs reports whether spelling s of v is found by both forms, as v's type.
func foundAs(d pii.Dictionary, k *pii.Keys, v value, s string) bool {
	typ, ok := d.Lookup(k.GenericHash(s))
	return ok && typ == v.typ && d.Contains(v.typ, k.TypedHash(v.typ, s, v.region))
}

// inParallel runs f(0..n-1) over GOMAXPROCS goroutines.
func inParallel(n int, f func(i int)) {
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < n; i += workers {
				f(i)
			}
		}()
	}
	wg.Wait()
}

// toFullWidth writes ASCII letters and digits in their full-width forms (NFKC
// maps them back).
func toFullWidth(s string) string {
	const fullWidthOffset = 0xFEE0
	var b strings.Builder
	for _, r := range s {
		if r >= '!' && r <= '~' {
			r += fullWidthOffset
		}
		b.WriteRune(r)
	}
	return b.String()
}

// A phone added with its column region is found by its +cc form.
func TestDictionaryPhoneRegion(t *testing.T) {
	k := newKeys(t, testMaster)
	d := openDict(t, t.TempDir(), k, dictOptions())
	require.NoError(t, buildWith(t, d, []value{{pii.EntityPhone, "0812-3456-7890", "ID"}}))
	require.True(t, d.Contains(pii.EntityPhone, k.TypedHash(pii.EntityPhone, "+62 812 3456 7890", "")))
}

// A value added to the delta is found at once, before any build, and the
// tokenizer finds it through the dictionary detector.
func TestDictionaryDeltaFoundBeforeBuild(t *testing.T) {
	k := newKeys(t, testMaster)
	d := openDict(t, t.TempDir(), k, dictOptions())
	require.True(t, d.NeedsBuild())
	v := value{pii.EntityPersonName, "Kaja Kask", ""}
	requireNotFound(t, d, k, v)
	require.NoError(t, d.Add(v.typ, v.text, v.region))
	requireFound(t, d, k, v)

	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(k, d, ""))...)
	out, reps, err := tz.Tokenize("Ask Kaja Kask about it")
	require.NoError(t, err)
	require.Len(t, reps, 1)
	require.NotContains(t, out, "Kaja")
	require.Zero(t, finalScan(t, tz, out))
}

// A value removed from the input is gone after the next build (M51-8).
func TestDictionaryRemovedValueGoneAfterBuild(t *testing.T) {
	k := newKeys(t, testMaster)
	d := openDict(t, t.TempDir(), k, dictOptions())
	a := value{pii.EntityEmail, "fixture.kept@example.com", ""}
	b := value{pii.EntityEmail, "fixture.removed@example.com", ""}
	require.NoError(t, buildWith(t, d, []value{a, b}))
	requireFound(t, d, k, b)
	require.NoError(t, buildWith(t, d, []value{a}))
	requireFound(t, d, k, a)
	requireNotFound(t, d, k, b)
}

// Values added while a build runs survive its commit; values added before it
// started drop out unless the build saw them; an aborted build keeps them all.
func TestDictionaryDeltaGenerations(t *testing.T) {
	k := newKeys(t, testMaster)
	d := openDict(t, t.TempDir(), k, dictOptions())
	before := value{pii.EntityOther, "EE000000000000000001", ""}
	during := value{pii.EntityOther, "EE000000000000000002", ""}
	require.NoError(t, d.Add(before.typ, before.text, before.region))

	b, err := d.StartBuild()
	require.NoError(t, err)
	_, err = d.StartBuild()
	require.ErrorIs(t, err, pii.ErrBuildRunning)
	require.NoError(t, d.Add(during.typ, during.text, during.region))
	requireFound(t, d, k, before)
	b.Abort()
	requireFound(t, d, k, before)
	requireFound(t, d, k, during)

	require.NoError(t, buildWith(t, d, nil))
	requireNotFound(t, d, k, before)
	requireNotFound(t, d, k, during)

	require.NoError(t, d.Add(before.typ, before.text, before.region))
	b, err = d.StartBuild()
	require.NoError(t, err)
	require.NoError(t, d.Add(during.typ, during.text, during.region))
	require.NoError(t, b.Commit(pii.ScanStats{}))
	requireNotFound(t, d, k, before)
	requireFound(t, d, k, during)
	require.ErrorIs(t, b.Commit(pii.ScanStats{}), pii.ErrBuildDone)
	require.Equal(t, 1, d.Status().DeltaValues)
}

// Reaching MaxDeltaEntries asks for an early rebuild; the delta takes values
// up to twice that, then refuses (the caller fails closed).
func TestDictionaryDeltaCap(t *testing.T) {
	k := newKeys(t, testMaster)
	o := dictOptions()
	o.MaxDeltaEntries = 3
	d := openDict(t, t.TempDir(), k, o)
	add := func(i int) error { return d.Add(pii.EntityOther, fmt.Sprintf("ID-%d", i), "") }
	for i := range 2 {
		require.NoError(t, add(i))
	}
	require.Empty(t, d.RebuildNeeded())
	require.NoError(t, add(2))
	require.Len(t, d.RebuildNeeded(), 1)
	for i := 3; i < 6; i++ {
		require.NoError(t, add(i))
	}
	require.ErrorIs(t, add(6), pii.ErrDeltaFull)
	<-d.RebuildNeeded()
	require.NoError(t, buildWith(t, d, nil))
	require.NoError(t, add(6))
}

// When 32-bit fingerprints would exceed the budget the build uses 16 bits and
// still finds every value; when 16 would not fit either, the previous base and
// the delta stay.
func TestDictionaryMemoryBudget(t *testing.T) {
	k := newKeys(t, testMaster)
	values := make([]value, sized(20_000, 10_000))
	for i := range values {
		values[i] = fakeValue(i)
	}
	stateDir := t.TempDir()
	d := openDict(t, stateDir, k, dictOptions())
	require.NoError(t, buildWith(t, d, values))
	fi, err := os.Stat(filepath.Join(stateDir, "pii", "dictionary.bin"))
	require.NoError(t, err)

	o := dictOptions()
	o.MaxMemoryBytes = fi.Size() - 1
	d16 := openDict(t, t.TempDir(), k, o)
	require.NoError(t, buildWith(t, d16, values))
	require.Equal(t, pii.FingerprintBits16, d16.FingerprintBits())
	// With 16 bits another type's filter may also answer for a value (a
	// harmless false positive), so only presence is checked.
	for _, v := range values {
		_, ok := d16.Lookup(k.GenericHash(v.text))
		require.True(t, ok)
		require.True(t, d16.Contains(v.typ, k.TypedHash(v.typ, v.text, v.region)))
	}

	o.MaxMemoryBytes = fi.Size() / 4
	small := openDict(t, t.TempDir(), k, o)
	require.NoError(t, buildWith(t, small, values[:10]))
	extra := value{pii.EntityOther, "EE999999999999999999", ""}
	require.NoError(t, small.Add(extra.typ, extra.text, extra.region))
	require.ErrorIs(t, buildWith(t, small, values), pii.ErrDictionaryOverBudget)
	for _, v := range values[:10] {
		requireFound(t, small, k, v)
	}
	requireFound(t, small, k, extra)
}

// The file is 0600 in a 0755 directory, status.json is 0644 with counts, the
// file holds no value, and a reopened dictionary maps it again.
func TestDictionaryFilesAndReopen(t *testing.T) {
	k := newKeys(t, testMaster)
	stateDir := t.TempDir()
	d := openDict(t, stateDir, k, dictOptions())
	values := []value{
		{pii.EntityEmail, "fixture.alice.tamm@example.com", ""},
		{pii.EntityPersonName, "Alice Tamm", ""},
		{pii.EntityPhone, "+44 7700 900123", ""},
	}
	require.NoError(t, buildWith(t, d, values))
	require.False(t, d.NeedsBuild())
	require.NoError(t, d.Add(pii.EntityOther, "EE123", ""))
	require.NoError(t, d.WriteStatus())

	dir := filepath.Join(stateDir, "pii")
	if runtime.GOOS != "windows" {
		requireMode(t, dir, 0o755)
		requireMode(t, filepath.Join(dir, "dictionary.bin"), 0o600)
		requireMode(t, filepath.Join(dir, "status.json"), 0o644)
	}
	for _, name := range []string{"dictionary.bin", "status.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		for _, v := range values {
			for _, part := range strings.Fields(v.text) {
				require.NotContains(t, strings.ToLower(string(raw)), strings.ToLower(part), name)
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "status.json"))
	require.NoError(t, err)
	var st map[string]any
	require.NoError(t, json.Unmarshal(raw, &st))
	require.Equal(t, map[string]any{
		// The two-word name is stored both ways: four generic forms.
		"dictionaryValues": 4.0, "deltaValues": 1.0, "fingerprintBits": 32.0,
		"lastScanAt": "2026-11-12T10:00:00Z", "lastScanColumns": 3.0, "lastScanRows": 3.0,
		"updatedAt": "2026-11-12T10:00:00Z",
	}, st)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "no temp file left")

	require.NoError(t, d.Close())
	again := openDict(t, stateDir, k, dictOptions())
	require.False(t, again.NeedsBuild())
	require.NoError(t, again.Discarded())
	for _, v := range values {
		requireFound(t, again, k, v)
	}
	require.Equal(t, int64(3), again.Status().LastScanRows)
}

func requireMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, mode, fi.Mode().Perm(), path)
}

// A file built with another key, another key version, or damaged is
// discarded at open (and rebuilt), never used and never a panic.
func TestDictionaryDiscardsUnusableFiles(t *testing.T) {
	k := newKeys(t, testMaster)
	v := value{pii.EntityEmail, "fixture.alice.tamm@example.com", ""}
	// hdrKeyVersion: the key version's offset in the header.
	const hdrKeyVersion = 12
	damage := map[string]func([]byte) []byte{
		"truncated":   func(b []byte) []byte { return b[:len(b)/2] },
		"header only": func(b []byte) []byte { return b[:64] },
		"flipped":     func(b []byte) []byte { b[len(b)/3] ^= 1; return b },
		"key version": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[hdrKeyVersion:], 2); return b },
		"garbage":     func(b []byte) []byte { return []byte(strings.Repeat("x", len(b))) },
		"tiny":        func([]byte) []byte { return []byte("BSLT") },
	}
	for name, change := range damage {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			d := openDict(t, stateDir, k, dictOptions())
			require.NoError(t, buildWith(t, d, []value{v}))
			require.NoError(t, d.Close())
			path := filepath.Join(stateDir, "pii", "dictionary.bin")
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, change(raw), 0o600))

			again := openDict(t, stateDir, k, dictOptions())
			require.True(t, again.NeedsBuild())
			require.Error(t, again.Discarded())
			requireNotFound(t, again, k, v)
			require.NoError(t, buildWith(t, again, []value{v}))
			requireFound(t, again, k, v)
		})
	}
	t.Run("other key", func(t *testing.T) {
		stateDir := t.TempDir()
		d := openDict(t, stateDir, k, dictOptions())
		require.NoError(t, buildWith(t, d, []value{v}))
		require.NoError(t, d.Close())
		other := newKeys(t, []byte("other-master-key-0123456789abcde"))
		again := openDict(t, stateDir, other, dictOptions())
		require.True(t, again.NeedsBuild())
		require.ErrorContains(t, again.Discarded(), "another key")
	})
}

// Concurrent lookups and adds while builds replace the base: every value
// added stays found (run with -race).
func TestDictionaryConcurrentRebuilds(t *testing.T) {
	k := newKeys(t, testMaster)
	d := openDict(t, t.TempDir(), k, dictOptions())
	base := make([]value, 500)
	for i := range base {
		base[i] = fakeValue(i)
	}
	require.NoError(t, buildWith(t, d, base))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				v := base[(i*7+w)%len(base)]
				typ, ok := d.Lookup(k.GenericHash(v.text))
				if !ok || typ != v.typ {
					t.Errorf("lost %s value during a rebuild", v.typ)
					return
				}
			}
		}()
	}
	for range 5 {
		require.NoError(t, buildWith(t, d, base))
	}
	close(stop)
	wg.Wait()
}

// status.json is written before the new base goes live: when that write
// fails, Commit fails and nothing changed (old base, delta values kept).
func TestDictionaryStatusWriteFailureLeavesOldBase(t *testing.T) {
	k := newKeys(t, testMaster)
	stateDir := t.TempDir()
	d := openDict(t, stateDir, k, dictOptions())
	old := value{pii.EntityEmail, "fixture.old@example.com", ""}
	added := value{pii.EntityOther, "EE000000000000000077", ""}
	fresh := value{pii.EntityEmail, "fixture.new@example.com", ""}
	require.NoError(t, buildWith(t, d, []value{old}))
	require.NoError(t, d.Add(added.typ, added.text, added.region))

	statusPath := filepath.Join(stateDir, "pii", "status.json")
	require.NoError(t, os.Remove(statusPath))
	// A non-empty directory in its place makes the rename of the new status.json fail.
	require.NoError(t, os.MkdirAll(filepath.Join(statusPath, "blocker"), 0o700))
	require.ErrorContains(t, buildWith(t, d, []value{fresh}), "status.json")
	requireFound(t, d, k, old)
	requireFound(t, d, k, added)
	requireNotFound(t, d, k, fresh)
	require.Equal(t, 1, d.Status().DeltaValues)

	require.NoError(t, os.RemoveAll(statusPath))
	require.NoError(t, buildWith(t, d, []value{fresh}))
	requireFound(t, d, k, fresh)
	requireNotFound(t, d, k, old)
}

// BenchmarkDictionaryLookup200k measures 200,000 generic lookups (the n-grams
// of a large request) against a base of 1,000,000 values, half of them hits.
// The hashes are computed before the loop: this is the dictionary's cost, not
// the HMAC's. Result (Apple M2, go1.26, no -race, -count=3): 9.6 to 11.8 ms per
// 200,000 lookups (about 55 ns each), 0 allocations.
func BenchmarkDictionaryLookup200k(b *testing.B) {
	const (
		baseValues = 1_000_000
		lookups    = 200_000
	)
	k, err := pii.NewKeys(testMaster)
	require.NoError(b, err)
	d, err := dictfile.Open(b.TempDir(), k, dictOptions())
	require.NoError(b, err)
	defer d.Close()
	build, err := d.StartBuild()
	require.NoError(b, err)
	for i := range baseValues {
		v := fakeValue(i)
		require.NoError(b, build.Add(v.typ, v.text, v.region))
	}
	require.NoError(b, build.Commit(pii.ScanStats{}))
	hashes := make([]pii.Hash, lookups)
	for i := range hashes {
		hashes[i] = k.GenericHash(fakeValue(i * 10).text)
	}
	b.ResetTimer()
	for b.Loop() {
		for _, h := range hashes {
			d.Lookup(h)
		}
	}
}

// A two-word PERSON_NAME is also found surname first ("Tamm, Alice", "TAMM
// Alice"), from the delta and from a build, at one extra generic hash per
// name. The reversed text gets the token of what it says, not of the stored
// order. Longer names and other types are found only in stored order.
func TestDictionaryTwoWordNameMatchesReversed(t *testing.T) {
	k := newKeys(t, testMaster)
	name := value{pii.EntityPersonName, "Alice Tamm", ""}
	long := value{pii.EntityPersonName, "Mari Liis Kask", ""}
	addr := value{pii.EntityAddress, "Fixture Lane", ""}
	byDelta := openDict(t, t.TempDir(), k, dictOptions())
	for _, v := range []value{name, long, addr} {
		require.NoError(t, byDelta.Add(v.typ, v.text, v.region))
	}
	byBuild := openDict(t, t.TempDir(), k, dictOptions())
	require.NoError(t, buildWith(t, byBuild, []value{name, long, addr}))
	for kind, d := range map[string]*pii.FuseDictionary{"delta": byDelta, "build": byBuild} {
		tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(k, d, ""))...)
		for _, c := range []struct{ in, span string }{
			{"ask Tamm, Alice about it", "Tamm, Alice"},
			{"TAMM Alice called", "TAMM Alice"},
			{"Alice Tamm called", "Alice Tamm"},
			{"tamm alice", "tamm alice"},
		} {
			out, reps, err := tz.Tokenize(c.in)
			require.NoError(t, err, "%s %q", kind, c.in)
			require.Len(t, reps, 1, "%s %q", kind, c.in)
			require.Equal(t, c.span, c.in[reps[0].Start:reps[0].End], "%s %q", kind, c.in)
			want, err := k.MakeToken(pii.EntityPersonName, c.span, "")
			require.NoError(t, err)
			require.Equal(t, want, reps[0].Token, "%s %q", kind, c.in)
			require.Zero(t, finalScan(t, tz, out), "%s %q", kind, c.in)
		}
		for _, in := range []string{"Kask Liis Mari", "Kask, Mari Liis", "Lane Fixture"} {
			_, reps, err := tz.Tokenize(in)
			require.NoError(t, err)
			require.Empty(t, reps, "%s %q", kind, in)
		}
	}
}

// A mapDict stores a two-word name both ways too.
func TestMapDictMatchesReversedNames(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPersonName, "Alice Tamm")
	_, ok := d.Lookup(k.GenericHash("Tamm Alice"))
	require.True(t, ok)
}

// Known limits of the reversed order: a pair of ordinary words reversed is
// still a match (it errs toward privacy), and a hyphen or an apostrophe
// splits a word, so such a name has three words and no reversed form.
func TestReversedNameKnownLimits(t *testing.T) {
	k := newKeys(t, testMaster)
	d := newMapDict()
	d.add(k, pii.EntityPersonName, "Will Smith")
	d.add(k, pii.EntityPersonName, "Mari-Liis Kask")
	tz := pii.NewTokenizer(k, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(k, d, ""))...)
	_, reps := tokenize(t, tz, "Smith will review it")
	require.Len(t, reps, 1)
	_, reps = tokenize(t, tz, "Kask, Mari-Liis")
	require.Empty(t, reps)
}
