package pii

import (
	"encoding/binary"
	"hash/crc32"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/FastFilter/xorfilter"
	"github.com/stretchr/testify/require"
)

const testKeyCheck = 0x0123456789abcdef

// The sizing formula matches what the library allocates, so the memory
// budget is checked against the real file size before a build.
func TestFuseSlotsMatchLibrary(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	sizes := make([]int, 0, 64)
	sizes = append(sizes, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 31, 100, 1000, 3907, 7777, 65536, 250_000)
	for n := 11; n < 400; n += 13 {
		sizes = append(sizes, n)
	}
	for _, n := range sizes {
		ks := make([]uint64, n)
		for i := range ks {
			ks[i] = rng.Uint64()
		}
		f, err := xorfilter.NewBinaryFuse[uint32](ks)
		require.NoError(t, err)
		require.Equal(t, uint64(len(f.Fingerprints)), fuseSlots(n), "n=%d", n)
	}
}

// randomFilterKeys spreads n random keys over the filters of entity type
// index ti, by shard, as a build does.
func randomFilterKeys(rng *rand.Rand, ti, n int) [][]uint64 {
	keys := make([][]uint64, filterCount())
	for range n {
		h := rng.Uint64()
		i := filterIndex(ti, Hash(h))
		keys[i] = append(keys[i], h)
	}
	for i := range keys {
		keys[i] = sortedUnique(keys[i])
	}
	return keys
}

// encodeDictionary writes a dictionary file and returns its bytes in an
// aligned buffer, as a mapping would give them.
func encodeDictionary(t testing.TB, keys [][]uint64, fpBits int) []byte {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), DictionaryFileName))
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, writeDictionary(f, keys, fpBits, 7, testKeyCheck))
	raw, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	return aligned(raw)
}

func aligned(raw []byte) []byte {
	words := make([]uint64, (len(raw)+dictArrayAlign-1)/dictArrayAlign+1)
	data := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(words))), len(raw))
	copy(data, raw)
	return data
}

func TestDictionaryFileRoundTrip(t *testing.T) {
	for _, fpBits := range []int{FingerprintBits32, FingerprintBits16} {
		rng := rand.New(rand.NewPCG(3, 4))
		keys := randomFilterKeys(rng, 2, 20_000)
		data := encodeDictionary(t, keys, fpBits)
		counts := make([]int, len(keys))
		for i := range keys {
			counts[i] = len(keys[i])
		}
		require.Equal(t, dictionaryFileSize(counts, fpBits), uint64(len(data)), "predicted size")
		b, err := parseDictionary(data, testKeyCheck)
		require.NoError(t, err)
		require.Equal(t, fpBits, b.bits)
		require.Equal(t, uint64(7), b.values)
		for _, ks := range keys {
			for _, k := range ks {
				require.True(t, b.contains(2, Hash(k)))
				typ, ok := b.lookup(Hash(k))
				require.True(t, ok)
				require.Equal(t, entityTypes[2], typ)
			}
		}
	}
}

// The measured false-positive rate is that of the fingerprint width: about
// 2^-32 per filter with 32 bits, 2^-16 with 16.
func TestDictionaryFalsePositiveRate(t *testing.T) {
	members := sized(200_000, 50_000)
	probes := sized(2_000_000, 500_000)
	rng := rand.New(rand.NewPCG(5, 6))
	keys := randomFilterKeys(rng, 0, members)
	member := map[uint64]bool{}
	for _, ks := range keys {
		for _, k := range ks {
			member[k] = true
		}
	}
	rate := func(fpBits int) int {
		b, err := parseDictionary(encodeDictionary(t, keys, fpBits), testKeyCheck)
		require.NoError(t, err)
		probe := rand.New(rand.NewPCG(7, 8))
		hits := 0
		for range probes {
			h := probe.Uint64()
			if !member[h] && b.contains(0, Hash(h)) {
				hits++
			}
		}
		return hits
	}
	// Expected probes / 2^32 = 0.0005 for 2e6 probes.
	require.LessOrEqual(t, rate(FingerprintBits32), 1)
	// Expected probes / 2^16 = 30.5 for 2e6 probes; the bounds keep the same
	// ratios (a third to double the whole-number expectation) at any size.
	fp16 := rate(FingerprintBits16)
	expected := probes >> 16
	require.GreaterOrEqual(t, fp16, expected/3)
	require.LessOrEqual(t, fp16, expected*2)
}

func smallDictionary(t testing.TB) []byte {
	t.Helper()
	rng := rand.New(rand.NewPCG(9, 10))
	keys := randomFilterKeys(rng, 1, 300)
	return encodeDictionary(t, keys, FingerprintBits32)
}

// A truncated file, a flipped bit, another key or another version is refused
// without a panic.
func TestParseDictionaryRefusesDamage(t *testing.T) {
	data := smallDictionary(t)
	_, err := parseDictionary(data, testKeyCheck)
	require.NoError(t, err)

	for n := 0; n < len(data); n += 97 {
		_, err := parseDictionary(aligned(data[:n]), testKeyCheck)
		require.ErrorIs(t, err, errDictionaryInvalid, "prefix %d", n)
	}
	for _, pos := range []int{0, hdrFormatVersion, hdrKeyVersion, hdrKeyCheck, hdrBits, hdrCRC, hdrFileSize, hdrTableOffset, dictHeaderSize, len(data) / 2, len(data) - 1} {
		bad := aligned(data)
		bad[pos] ^= 0x40
		_, err := parseDictionary(bad, testKeyCheck)
		require.ErrorIs(t, err, errDictionaryInvalid, "flip at %d", pos)
	}
	_, err = parseDictionary(data, testKeyCheck+1)
	require.ErrorIs(t, err, errDictionaryInvalid)
	_, err = parseDictionary(aligned(append(data, 0)), testKeyCheck)
	require.ErrorIs(t, err, errDictionaryInvalid)
}

// fixCRC recomputes the checksum so a mutation reaches the structural checks.
func fixCRC(data []byte) {
	if len(data) < dictHeaderSize {
		return
	}
	binary.LittleEndian.PutUint32(data[hdrCRC:], crc32.Checksum(data[dictHeaderSize:], castagnoli))
}

// The loader never panics, and a file it accepts never panics a lookup.
func FuzzParseDictionary(f *testing.F) {
	f.Add(smallDictionary(f))
	f.Add([]byte(dictMagic))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, fix := range []bool{false, true} {
			data := aligned(raw)
			if fix {
				fixCRC(data)
			}
			b, err := parseDictionary(data, testKeyCheck)
			if err != nil {
				require.ErrorIs(t, err, errDictionaryInvalid)
				continue
			}
			rng := rand.New(rand.NewPCG(uint64(len(raw)), 1))
			for range 2000 {
				h := Hash(rng.Uint64())
				b.lookup(h)
				b.contains(int(rng.Uint64()%uint64(len(entityTypes))), h)
			}
		}
	})
}

// A base is unmapped only when the last lookup holding it is done.
func TestBaseReleasedAfterLastReference(t *testing.T) {
	unmapped := 0
	b := newMappedBase(emptyBase(), func() error { unmapped++; return nil })
	require.True(t, b.tryAcquire())
	b.release() // the dictionary's own reference
	require.Equal(t, 0, unmapped)
	b.release() // the lookup's
	require.Equal(t, 1, unmapped)
	require.False(t, b.tryAcquire())
}
