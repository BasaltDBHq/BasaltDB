package plugin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInstallSameUser: same-user mode installs under t.TempDir() without
// root, into <root>/<name>/<instance>/<manifest-sha256>/, copying only the
// manifest, its signature and the listed files, and the copy verifies.
func TestInstallSameUser(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.install("")

	require.Equal(t, filepath.Join(f.configDir, "plugins", "acme-ner", DefaultInstance, v.ManifestSHA256), v.Dir)
	require.Len(t, v.ManifestSHA256, 64)
	signer, err := KeyID(&f.signer.PublicKey)
	require.NoError(t, err)
	require.Equal(t, signer, v.SignerKeyID)
	require.Equal(t, "acme-ner", v.Manifest.Name)

	require.ElementsMatch(t, []string{ManifestFile, SignatureFile, "bin", "model"}, entries(t, v.Dir), "the source's README is not copied")
	require.Equal(t, []string{v.ManifestSHA256}, entries(t, filepath.Dir(v.Dir)), "no temporary copy is left")
	fi, err := os.Stat(filepath.Join(v.Dir, "bin", "acme-ner"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm())
	fi, err = os.Stat(filepath.Join(v.Dir, "model", "weights.bin"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
	fi, err = os.Stat(v.Dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm())

	got, err := f.verify(DefaultInstance, v.ManifestSHA256)
	require.NoError(t, err)
	require.Equal(t, v.ManifestSHA256, got.ManifestSHA256)
	require.Equal(t, v.Dir, got.Dir)

	// Installing the same manifest again keeps the copy.
	again := f.install(DefaultInstance)
	require.Equal(t, v.Dir, again.Dir)
	require.Equal(t, []string{v.ManifestSHA256}, entries(t, filepath.Dir(v.Dir)))
}

// TestSignatureVectorInstalls: the contract's signed vector installs once its
// publisher key is trusted, and its key id is the one computed from the key.
func TestSignatureVectorInstalls(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	vector := filepath.Join(contractTestdata, "signed")

	_, err := Install(vector, f.root, "", f.trust, ModeSameUser)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Contains(t, ve.Why, "not trusted", "the vector's key is not trusted yet")

	pemBytes, err := os.ReadFile(filepath.Join(vector, "publisher.pub"))
	require.NoError(t, err)
	id, added, err := f.trust.Add(pemBytes)
	require.NoError(t, err)
	require.True(t, added)
	require.Equal(t, "jNZPxNG5htlwfhg4ZgknAA", id)

	v, err := Install(vector, f.root, "", f.trust, ModeSameUser)
	require.NoError(t, err)
	require.Equal(t, id, v.SignerKeyID)
	require.ElementsMatch(t, []string{ManifestFile, SignatureFile, "bin"}, entries(t, v.Dir))
}

// TestChangedByteRefused: a changed byte in a listed file, in the source or
// in the installed copy, is refused, naming the file but not its contents.
func TestChangedByteRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.install("")

	bin := filepath.Join(v.Dir, "bin", "acme-ner")
	require.NoError(t, os.WriteFile(bin, []byte(strings.Replace(testBinary, "echo", "eCho", 1)), 0o755))
	_, err := f.verify(DefaultInstance, v.ManifestSHA256)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Equal(t, bin, ve.File)
	require.Contains(t, ve.Why, "SHA-256")
	requireNoSecrets(t, err)

	// The same change in the source is refused at add, and nothing stays.
	g := newFixture(t)
	srcModel := filepath.Join(g.src, "model", "weights.bin")
	require.NoError(t, os.WriteFile(srcModel, []byte("TOP-SECRET-MODEL-WEIGHTz"), 0o644))
	_, err = Install(g.src, g.root, "", g.trust, ModeSameUser)
	ve = requireRefused(t, err, RefusedNotTrusted)
	require.True(t, strings.HasSuffix(ve.File, filepath.Join("model", "weights.bin")))
	requireNoSecrets(t, err)
	require.Empty(t, entries(t, filepath.Join(g.root, "acme-ner", DefaultInstance)), "a failed add leaves no copy")

	// A changed manifest byte fails its signature.
	h := newFixture(t)
	m := localManifest()
	m[len(m)-2] = ' '
	require.NoError(t, os.WriteFile(filepath.Join(h.src, ManifestFile), m, 0o644))
	_, err = Install(h.src, h.root, "", h.trust, ModeSameUser)
	ve = requireRefused(t, err, RefusedNotTrusted)
	require.Contains(t, ve.Why, "does not verify")
}

// TestUntrustedKeyRefused: a manifest re-signed by a key that is not in the
// trust store is refused.
func TestUntrustedKeyRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	other, err := GenerateKey()
	require.NoError(t, err)
	f.writeSigned(f.src, localManifest(), other)
	_, err = Install(f.src, f.root, "", f.trust, ModeSameUser)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Contains(t, ve.Why, "not trusted")
	require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner", DefaultInstance)))
}

// TestSourceChangedAfterAddHasNoEffect: the copy is what was read from the
// source at add; a change to the source after staging, or after install,
// does not reach it.
func TestSourceChangedAfterAddHasNoEffect(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s, err := Stage(f.src, f.root, "", f.trust, ModeSameUser)
	require.NoError(t, err)
	// Between verification and consent the source is swapped.
	require.NoError(t, os.WriteFile(filepath.Join(f.src, "bin", "acme-ner"), []byte("#!/bin/sh\nevil\n"), 0o755))
	dir, err := s.Commit()
	require.NoError(t, err)
	b, err := os.ReadFile(filepath.Join(dir, "bin", "acme-ner"))
	require.NoError(t, err)
	require.Equal(t, testBinary, string(b))
	_, err = f.verify(DefaultInstance, s.ManifestSHA256)
	require.NoError(t, err)

	// A source re-signed with new contents after install changes nothing.
	f.writeSigned(f.src, append(localManifest(), ' '), f.signer)
	_, err = f.verify(DefaultInstance, s.ManifestSHA256)
	require.NoError(t, err)
}

// TestStageDiscard: a declined consent leaves nothing behind, and a staged
// copy is readable by its owner only until it is committed.
func TestStageDiscard(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s, err := Stage(f.src, f.root, "", f.trust, ModeSameUser)
	require.NoError(t, err)
	fi, err := os.Stat(s.Dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	require.True(t, strings.HasPrefix(filepath.Base(s.Dir), stagingPrefix))
	require.NoError(t, s.Discard())
	require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner", DefaultInstance)))
	_, err = s.Commit()
	require.Error(t, err, "a discarded copy cannot be committed")
}

// TestSymlinkRefused: a symlink in the source, escaping it or not, and a
// symlink in the installed copy, are refused.
func TestSymlinkRefused(t *testing.T) {
	t.Parallel()

	// A listed file that links outside the source, to a file with the right
	// hash, is still refused: the copy never follows a link.
	f := newFixture(t)
	outside := filepath.Join(f.base, "outside")
	require.NoError(t, os.WriteFile(outside, []byte(testModel), 0o644))
	model := filepath.Join(f.src, "model", "weights.bin")
	require.NoError(t, os.Remove(model))
	require.NoError(t, os.Symlink(outside, model))
	_, err := Install(f.src, f.root, "", f.trust, ModeSameUser)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Equal(t, model, ve.File)

	// A directory on the way that links elsewhere is refused.
	g := newFixture(t)
	elsewhere := filepath.Join(g.base, "elsewhere")
	require.NoError(t, os.Rename(filepath.Join(g.src, "model"), elsewhere))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(g.src, "model")))
	_, err = Install(g.src, g.root, "", g.trust, ModeSameUser)
	requireRefused(t, err, RefusedNotTrusted)

	// A file of the installed copy replaced by a link is refused at start.
	h := newFixture(t)
	v := h.install("")
	installed := filepath.Join(v.Dir, "model", "weights.bin")
	require.NoError(t, os.Remove(installed))
	require.NoError(t, os.Symlink(outside, installed))
	_, err = h.verify(DefaultInstance, v.ManifestSHA256)
	ve = requireRefused(t, err, RefusedNotTrusted)
	require.Equal(t, installed, ve.File)
	require.Contains(t, ve.Why, "symlink")
}

// TestPathRule: a group- or other-writable directory or file in the copy,
// in the trust store, or above the config directory, is refused, as is a
// symlink above the root that root does not own.
func TestPathRule(t *testing.T) {
	t.Parallel()
	cases := map[string]func(f *fixture, v Verified) string{
		"copy directory": func(_ *fixture, v Verified) string { return v.Dir },
		"copy subdir":    func(_ *fixture, v Verified) string { return filepath.Join(v.Dir, "bin") },
		"copy file":      func(_ *fixture, v Verified) string { return filepath.Join(v.Dir, "model", "weights.bin") },
		"manifest":       func(_ *fixture, v Verified) string { return filepath.Join(v.Dir, ManifestFile) },
		"instance dir":   func(_ *fixture, v Verified) string { return filepath.Dir(v.Dir) },
		"plugin root":    func(f *fixture, _ Verified) string { return f.root },
		"trust store":    func(f *fixture, _ Verified) string { return f.trust.Dir() },
		"trusted key": func(f *fixture, _ Verified) string {
			id, err := KeyID(&f.signer.PublicKey)
			require.NoError(f.t, err)
			return filepath.Join(f.trust.Dir(), id+trustFileExt)
		},
		"config dir":       func(f *fixture, _ Verified) string { return f.configDir },
		"above config dir": func(f *fixture, _ Verified) string { return f.base },
	}
	for name, target := range cases {
		for _, bits := range []os.FileMode{0o020, 0o002} {
			t.Run(name+"/"+bits.String(), func(t *testing.T) {
				t.Parallel()
				f := newFixture(t)
				v := f.install("")
				_, err := f.verify(DefaultInstance, v.ManifestSHA256)
				require.NoError(t, err)

				p := target(f, v)
				fi, err := os.Stat(p)
				require.NoError(t, err)
				require.NoError(t, os.Chmod(p, fi.Mode().Perm()|bits))
				_, err = f.verify(DefaultInstance, v.ManifestSHA256)
				ve := requireRefused(t, err, RefusedNotTrusted)
				require.Equal(t, p, ve.File)
				require.Contains(t, ve.Why, "written by group or others")
				require.NoError(t, os.Chmod(p, fi.Mode().Perm()))
			})
		}
	}

	t.Run("user symlink above root", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		v := f.install("")
		link := filepath.Join(f.base, "link")
		require.NoError(t, os.Symlink(f.base, link))
		root := Root(ModeSameUser, runtime.GOOS, filepath.Join(link, "config"))
		_, err := Verify(root, EntryKey{Name: "acme-ner", Instance: DefaultInstance}, v.ManifestSHA256, f.trust, ModeSameUser)
		ve := requireRefused(t, err, RefusedNotTrusted)
		require.Equal(t, link, ve.File)
		require.Contains(t, ve.Why, "symlink not owned by root")
	})

	t.Run("extra file in copy", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		v := f.install("")
		extra := filepath.Join(v.Dir, "bin", "helper")
		require.NoError(t, os.WriteFile(extra, []byte("x"), 0o644))
		_, err := f.verify(DefaultInstance, v.ManifestSHA256)
		ve := requireRefused(t, err, RefusedNotTrusted)
		require.Equal(t, extra, ve.File)
	})

	t.Run("missing file in copy", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		v := f.install("")
		require.NoError(t, os.Remove(filepath.Join(v.Dir, "model", "weights.bin")))
		_, err := f.verify(DefaultInstance, v.ManifestSHA256)
		requireRefused(t, err, RefusedNotTrusted)
	})
}

// TestServiceModeRequiresRoot: in service mode the required owner is root,
// so a tree the test's user owns is refused. Tests never run as root.
func TestServiceModeRequiresRoot(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("the test needs a user other than root")
	}
	f := newFixture(t)
	v := f.install("")
	trust, err := NewTrustStore(f.configDir, ModeService)
	require.NoError(t, err)
	_, err = Verify(f.root, EntryKey{Name: "acme-ner", Instance: DefaultInstance}, v.ManifestSHA256, trust, ModeService)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Contains(t, ve.Why, "owned by")

	// From the root down the owner must be root itself, not just any user
	// root would allow above it.
	_, err = checkStrict(v.Dir, rootUID)
	requireRefused(t, err, RefusedNotTrusted)
	uid, err := currentUID()
	require.NoError(t, err)
	_, err = checkStrict(v.Dir, uid)
	require.NoError(t, err)
}

// TestRemoteManifestSignatureOnly: a remote plugin's copy is the manifest and
// its signature, verified by signature only; anything else in it is
// refused.
func TestRemoteManifestSignatureOnly(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src := filepath.Join(f.base, "remote")
	f.writeSigned(src, []byte(remoteManifest), f.signer)

	v, err := Install(src, f.root, "", f.trust, ModeSameUser)
	require.NoError(t, err)
	require.True(t, v.Manifest.Endpoint.IsRemote())
	require.Empty(t, v.Manifest.Files)
	require.ElementsMatch(t, []string{ManifestFile, SignatureFile}, entries(t, v.Dir))
	key := EntryKey{Name: "acme-cloud", Instance: DefaultInstance}
	_, err = Verify(f.root, key, v.ManifestSHA256, f.trust, ModeSameUser)
	require.NoError(t, err)

	extra := filepath.Join(v.Dir, "bin")
	require.NoError(t, os.WriteFile(extra, []byte("x"), 0o644))
	_, err = Verify(f.root, key, v.ManifestSHA256, f.trust, ModeSameUser)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Equal(t, extra, ve.File)
	require.NoError(t, os.Remove(extra))

	// The signature still covers every byte.
	other, err := GenerateKey()
	require.NoError(t, err)
	f.writeSigned(src, []byte(remoteManifest), other)
	_, err = Install(src, f.root, "second", f.trust, ModeSameUser)
	requireRefused(t, err, RefusedNotTrusted)
}

// TestInstancesAreSeparate: two instances of one plugin get two copies, and
// changing or removing one does not affect the other.
func TestInstancesAreSeparate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := f.install(DefaultInstance)
	b := f.install("client_x")
	require.NotEqual(t, a.Dir, b.Dir)
	require.Equal(t, a.ManifestSHA256, b.ManifestSHA256)
	require.Equal(t, filepath.Join(f.root, "acme-ner", "client_x", b.ManifestSHA256), b.Dir)

	require.NoError(t, os.WriteFile(filepath.Join(b.Dir, "model", "weights.bin"), []byte("changed"), 0o644))
	_, err := f.verify("client_x", b.ManifestSHA256)
	requireRefused(t, err, RefusedNotTrusted)
	_, err = f.verify(DefaultInstance, a.ManifestSHA256)
	require.NoError(t, err, "a change to one instance leaves the other intact")

	require.NoError(t, os.RemoveAll(filepath.Join(f.root, "acme-ner", "client_x")))
	_, err = f.verify(DefaultInstance, a.ManifestSHA256)
	require.NoError(t, err)

	// Re-adding replaces a copy that no longer verifies.
	again := f.install("client_x")
	_, err = f.verify("client_x", again.ManifestSHA256)
	require.NoError(t, err)
}

// TestReinstallReplacesBrokenCopy: when <sha>/ exists but fails, add puts a
// verified copy in its place.
func TestReinstallReplacesBrokenCopy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.install("")
	require.NoError(t, os.WriteFile(filepath.Join(v.Dir, "bin", "acme-ner"), []byte("broken"), 0o755))
	_, err := f.verify(DefaultInstance, v.ManifestSHA256)
	requireRefused(t, err, RefusedNotTrusted)

	again := f.install("")
	require.Equal(t, v.Dir, again.Dir)
	_, err = f.verify(DefaultInstance, v.ManifestSHA256)
	require.NoError(t, err)
	require.Equal(t, []string{v.ManifestSHA256}, entries(t, filepath.Dir(v.Dir)), "the old copy is removed")
}

// TestVerifyEntryChecks: the entry's manifestSha256, name and instance must
// match the installed copy.
func TestVerifyEntryChecks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.install("")

	other := strings.Repeat("0", 64)
	require.NoError(t, os.Rename(v.Dir, filepath.Join(filepath.Dir(v.Dir), other)))
	_, err := f.verify(DefaultInstance, other)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Contains(t, ve.Why, "manifestSha256")
	require.NoError(t, os.Rename(filepath.Join(filepath.Dir(v.Dir), other), v.Dir))

	for _, bad := range []string{"", "ABC", "../x", strings.Repeat("a", 63)} {
		_, err = f.verify(DefaultInstance, bad)
		requireRefused(t, err, RefusedNotTrusted)
	}
	for _, inst := range []string{"", "../x", "Client", "x/y"} {
		_, err = f.verify(inst, v.ManifestSHA256)
		requireRefused(t, err, RefusedBadManifest)
	}
	_, err = Verify(f.root, EntryKey{Name: "../acme-ner", Instance: DefaultInstance}, v.ManifestSHA256, f.trust, ModeSameUser)
	requireRefused(t, err, RefusedBadManifest)
	_, err = Verify(f.root, EntryKey{Name: "acme-ner", Instance: DefaultInstance}, v.ManifestSHA256, f.trust, Mode("ROOTLESS"))
	require.ErrorIs(t, err, errUnknownMode)
}
