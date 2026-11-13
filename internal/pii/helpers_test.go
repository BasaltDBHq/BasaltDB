package pii_test

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// testMaster is a fixed 32-byte master key for tests only.
// fullRun reports whether the exhaustive sizes are wanted: set
// BASALTDB_TEST_FULL=1 to run every case at its full size. The default path
// runs smaller, sampled loops so a race-enabled run stays short.
func fullRun() bool { return os.Getenv("BASALTDB_TEST_FULL") == "1" }

// sized is full when fullRun, light otherwise.
func sized(full, light int) int {
	if fullRun() {
		return full
	}
	return light
}

var testMaster = []byte("test-master-key-0123456789abcdef")

func newKeys(t *testing.T, master []byte) *pii.Keys {
	t.Helper()
	k, err := pii.NewKeys(master)
	require.NoError(t, err)
	return k
}

// mapDict is an exact in-memory pii.Dictionary for tests. The real one (fuse
// filters plus a delta) is built on the same hashes.
type mapDict struct {
	generic map[pii.Hash]pii.EntityType
	typed   map[pii.EntityType]map[pii.Hash]bool
}

func newMapDict() *mapDict {
	return &mapDict{generic: map[pii.Hash]pii.EntityType{}, typed: make(map[pii.EntityType]map[pii.Hash]bool)}
}

// add stores a value. Values here are written with +cc, so no phone region.
func (d *mapDict) add(k *pii.Keys, t pii.EntityType, value string) {
	for _, h := range k.GenericHashes(t, value) {
		d.generic[h] = t
	}
	if d.typed[t] == nil {
		d.typed[t] = map[pii.Hash]bool{}
	}
	d.typed[t][k.TypedHash(t, value, "")] = true
}

func (d *mapDict) Lookup(h pii.Hash) (pii.EntityType, bool) {
	t, ok := d.generic[h]
	return t, ok
}

func (d *mapDict) Contains(t pii.EntityType, h pii.Hash) bool { return d.typed[t][h] }

// loadFixture reads testdata/dictionary.tsv (fake values) into a mapDict.
func loadFixture(t *testing.T, k *pii.Keys) *mapDict {
	t.Helper()
	f, err := os.Open("testdata/dictionary.tsv")
	require.NoError(t, err)
	defer f.Close()
	d := newMapDict()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		typ, val, ok := strings.Cut(line, "\t")
		require.True(t, ok, line)
		d.add(k, pii.EntityType(typ), val)
	}
	require.NoError(t, sc.Err())
	return d
}

// finalScan counts the values the tokenizer's detectors still find in s.
func finalScan(t *testing.T, tz *pii.Tokenizer, s string) int {
	t.Helper()
	n, err := tz.FinalScan(s)
	require.NoError(t, err)
	return n
}

// newTokenizer is the default tokenizer (patterns, then the dictionary) over
// the fixture dictionary.
func newTokenizer(t *testing.T) *pii.Tokenizer {
	t.Helper()
	k := newKeys(t, testMaster)
	dd := pii.NewDictionaryDetector(k, loadFixture(t, k), "")
	return pii.NewTokenizer(k, "", append(pii.PatternDetectors(), dd)...)
}
