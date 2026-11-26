package plugin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/testkit/pluginsign"
)

// TestInstallSameUser: same-user mode installs under t.TempDir() without
// root, into <root>/<name>/<instance>/<manifest-sha256>/, copying only the
// manifest, its signature and the listed files, and the copy verifies.
func TestInstallSameUser(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.install("")

	require.Equal(t, filepath.Join(f.configDir, "plugins", "acme-ner", pluginmodel.DefaultInstance, v.ManifestSHA256), v.Dir)
	require.Len(t, v.ManifestSHA256, 64)
	signer, err := pluginsign.KeyID(&f.signer.PublicKey)
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

	got, err := f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
	require.NoError(t, err)
	require.Equal(t, v.ManifestSHA256, got.ManifestSHA256)
	require.Equal(t, v.Dir, got.Dir)

	// Installing the same manifest again keeps the copy.
	again := f.install(pluginmodel.DefaultInstance)
	require.Equal(t, v.Dir, again.Dir)
	require.Equal(t, []string{v.ManifestSHA256}, entries(t, filepath.Dir(v.Dir)))
}

// TestSignatureVectorInstalls: the contract's signed vector installs once its
// publisher key is trusted, and its key id is the one computed from the key.
func TestSignatureVectorInstalls(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	vector := filepath.Join(contractTestdata, "signed")

	_, err := installCopy(vector, f.root, "", f.trust)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Contains(t, ve.Why, "not trusted", "the vector's key is not trusted yet")

	pemBytes, err := os.ReadFile(filepath.Join(vector, "publisher.pub"))
	require.NoError(t, err)
	id, added, err := f.trust.Add(pemBytes)
	require.NoError(t, err)
	require.True(t, added)
	require.Equal(t, "jNZPxNG5htlwfhg4ZgknAA", id)

	v, err := installCopy(vector, f.root, "", f.trust)
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
	_, err := f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, bin, ve.File)
	require.Contains(t, ve.Why, "SHA-256")
	requireNoSecrets(t, err)

	// The same change in the source is refused at add, and nothing stays.
	g := newFixture(t)
	srcModel := filepath.Join(g.src, "model", "weights.bin")
	require.NoError(t, os.WriteFile(srcModel, []byte("TOP-SECRET-MODEL-WEIGHTz"), 0o644))
	_, err = installCopy(g.src, g.root, "", g.trust)
	ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.True(t, strings.HasSuffix(ve.File, filepath.Join("model", "weights.bin")))
	requireNoSecrets(t, err)
	require.Empty(t, entries(t, filepath.Join(g.root, "acme-ner", pluginmodel.DefaultInstance)), "a failed add leaves no copy")

	// A changed manifest byte fails its signature.
	h := newFixture(t)
	m := localManifest()
	m[len(m)-2] = ' '
	require.NoError(t, os.WriteFile(filepath.Join(h.src, ManifestFile), m, 0o644))
	_, err = installCopy(h.src, h.root, "", h.trust)
	ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Contains(t, ve.Why, "does not verify")
}

// TestUntrustedKeyRefused: a manifest re-signed by a key that is not in the
// trust store is refused.
func TestUntrustedKeyRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	other, err := pluginsign.GenerateKey()
	require.NoError(t, err)
	f.writeSigned(f.src, localManifest(), other)
	_, err = installCopy(f.src, f.root, "", f.trust)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Contains(t, ve.Why, "not trusted")
	require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner", pluginmodel.DefaultInstance)))
}

// TestSourceChangedAfterAddHasNoEffect: the copy is what was read from the
// source at add; a change to the source after staging, or after install,
// does not reach it.
func TestSourceChangedAfterAddHasNoEffect(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s, err := Stage(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser)
	require.NoError(t, err)
	// Between verification and consent the source is swapped.
	require.NoError(t, os.WriteFile(filepath.Join(f.src, "bin", "acme-ner"), []byte("#!/bin/sh\nevil\n"), 0o755))
	dir, err := s.Commit()
	require.NoError(t, err)
	b, err := os.ReadFile(filepath.Join(dir, "bin", "acme-ner"))
	require.NoError(t, err)
	require.Equal(t, testBinary, string(b))
	_, err = f.verify(pluginmodel.DefaultInstance, s.ManifestSHA256)
	require.NoError(t, err)

	// A source re-signed with new contents after install changes nothing.
	f.writeSigned(f.src, append(localManifest(), ' '), f.signer)
	_, err = f.verify(pluginmodel.DefaultInstance, s.ManifestSHA256)
	require.NoError(t, err)
}

// TestStageDiscard: a declined consent leaves nothing behind, and a staged
// copy is readable by its owner only until it is committed.
func TestStageDiscard(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s, err := Stage(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser)
	require.NoError(t, err)
	fi, err := os.Stat(s.Dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	require.True(t, strings.HasPrefix(filepath.Base(s.Dir), stagingPrefix))
	require.NoError(t, s.Discard())
	require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner", pluginmodel.DefaultInstance)))
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
	_, err := installCopy(f.src, f.root, "", f.trust)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, model, ve.File)

	// A directory on the way that links elsewhere is refused.
	g := newFixture(t)
	elsewhere := filepath.Join(g.base, "elsewhere")
	require.NoError(t, os.Rename(filepath.Join(g.src, "model"), elsewhere))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(g.src, "model")))
	_, err = installCopy(g.src, g.root, "", g.trust)
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)

	// A link that stays inside the source is refused too, for a listed
	// file, the manifest and its signature.
	for _, rel := range []string{filepath.Join("model", "weights.bin"), ManifestFile, SignatureFile} {
		k := newFixture(t)
		target := filepath.Join(k.src, "same-bytes")
		orig := filepath.Join(k.src, rel)
		require.NoError(t, os.Rename(orig, target))
		require.NoError(t, os.Symlink(target, orig))
		_, err = installCopy(k.src, k.root, "", k.trust)
		ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
		require.Equal(t, orig, ve.File, rel)
		require.Contains(t, ve.Why, "symlink", rel)
		require.Empty(t, entries(t, filepath.Join(k.root, "acme-ner", pluginmodel.DefaultInstance)), rel)
	}

	// A file of the installed copy replaced by a link is refused at start.
	h := newFixture(t)
	v := h.install("")
	installed := filepath.Join(v.Dir, "model", "weights.bin")
	require.NoError(t, os.Remove(installed))
	require.NoError(t, os.Symlink(outside, installed))
	_, err = h.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
	ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, installed, ve.File)
	require.Contains(t, ve.Why, "symlink")
}

// TestPathRule: a group- or other-writable directory or file in the copy,
// in the trust store, or above the config directory, is refused, as is a
// symlink above the root that root does not own.
func TestPathRule(t *testing.T) {
	t.Parallel()
	cases := map[string]func(f *fixture, v pluginmodel.Verified) string{
		"copy directory": func(_ *fixture, v pluginmodel.Verified) string { return v.Dir },
		"copy subdir":    func(_ *fixture, v pluginmodel.Verified) string { return filepath.Join(v.Dir, "bin") },
		"copy file":      func(_ *fixture, v pluginmodel.Verified) string { return filepath.Join(v.Dir, "model", "weights.bin") },
		"manifest":       func(_ *fixture, v pluginmodel.Verified) string { return filepath.Join(v.Dir, ManifestFile) },
		"instance dir":   func(_ *fixture, v pluginmodel.Verified) string { return filepath.Dir(v.Dir) },
		"plugin root":    func(f *fixture, _ pluginmodel.Verified) string { return f.root },
		"trust store":    func(f *fixture, _ pluginmodel.Verified) string { return f.trust.Dir() },
		"trusted key": func(f *fixture, _ pluginmodel.Verified) string {
			id, err := pluginsign.KeyID(&f.signer.PublicKey)
			require.NoError(f.t, err)
			return filepath.Join(f.trust.Dir(), id+trustFileExt)
		},
		"config dir":       func(f *fixture, _ pluginmodel.Verified) string { return f.configDir },
		"above config dir": func(f *fixture, _ pluginmodel.Verified) string { return f.base },
	}
	for name, target := range cases {
		for _, bits := range []os.FileMode{0o020, 0o002} {
			t.Run(name+"/"+bits.String(), func(t *testing.T) {
				t.Parallel()
				f := newFixture(t)
				v := f.install("")
				_, err := f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
				require.NoError(t, err)

				p := target(f, v)
				fi, err := os.Stat(p)
				require.NoError(t, err)
				require.NoError(t, os.Chmod(p, fi.Mode().Perm()|bits))
				_, err = f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
				ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
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
		root, err := Root(pluginmodel.ModeSameUser, runtime.GOOS, filepath.Join(link, "config"))
		require.NoError(t, err)
		_, err = Verify(root, pluginmodel.EntryKey{Name: "acme-ner", Instance: pluginmodel.DefaultInstance}, v.ManifestSHA256, f.trust, pluginmodel.ModeSameUser)
		ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
		require.Equal(t, link, ve.File)
		require.Contains(t, ve.Why, "symlink not owned by root")
	})

	t.Run("extra file in copy", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		v := f.install("")
		extra := filepath.Join(v.Dir, "bin", "helper")
		require.NoError(t, os.WriteFile(extra, []byte("x"), 0o644))
		_, err := f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
		ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
		require.Equal(t, extra, ve.File)
	})

	t.Run("missing file in copy", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		v := f.install("")
		require.NoError(t, os.Remove(filepath.Join(v.Dir, "model", "weights.bin")))
		_, err := f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
		requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	})
}

// TestStageChecksDestination: the path rule holds where the copy is written
// before anything is written there; a refused add leaves no staging copy.
func TestStageChecksDestination(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	instDir := filepath.Join(f.root, "acme-ner", pluginmodel.DefaultInstance)
	require.NoError(t, os.MkdirAll(instDir, 0o755))
	require.NoError(t, os.Chmod(instDir, 0o775))
	_, err := installCopy(f.src, f.root, "", f.trust)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, instDir, ve.File)
	require.Empty(t, entries(t, instDir))
}

// TestNothingCreatedUnderWritableDir: add and trust apply the path rule to
// the nearest existing directory before creating any, so nothing is created
// (or chmodded) inside a directory another user could write.
func TestNothingCreatedUnderWritableDir(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	require.NoError(t, os.Chmod(f.configDir, 0o770))
	_, err := installCopy(f.src, f.root, "", f.trust)
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	_, statErr := os.Lstat(f.root)
	require.ErrorIs(t, statErr, os.ErrNotExist, "no plugin root was created")

	g := newFixture(t)
	require.NoError(t, os.RemoveAll(g.trust.Dir()))
	require.NoError(t, os.Chmod(g.configDir, 0o770))
	pemBytes, err := MarshalPublicKey(&g.signer.PublicKey)
	require.NoError(t, err)
	_, _, err = g.trust.Add(pemBytes)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, g.configDir, ve.File)
	_, statErr = os.Lstat(g.trust.Dir())
	require.ErrorIs(t, statErr, os.ErrNotExist, "no trust store was created")

	// A missing trust store still checks the directories above it.
	_, err = installCopy(g.src, g.root, "", g.trust)
	ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, g.configDir, ve.File)
}

// TestTrustStoreModeMustMatch: a trust store made for another mode, or not
// made by NewTrustStore, is refused.
func TestTrustStoreModeMustMatch(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("the test needs a user other than root")
	}
	f := newFixture(t)
	v := f.install("")
	service, err := NewTrustStore(testFiles, pluginmodel.ModeService, runtime.GOOS, f.configDir)
	require.NoError(t, err)
	key := pluginmodel.EntryKey{Name: "acme-ner", Instance: pluginmodel.DefaultInstance}
	_, err = Verify(f.root, key, v.ManifestSHA256, service, pluginmodel.ModeSameUser)
	require.ErrorIs(t, err, errTrustMode)
	_, err = Verify(f.root, key, v.ManifestSHA256, TrustStore{}, pluginmodel.ModeSameUser)
	require.ErrorIs(t, err, errTrustMode)
	_, err = Stage(f.src, f.root, "", service, pluginmodel.ModeSameUser)
	require.ErrorIs(t, err, errTrustMode)
	_, err = Root(pluginmodel.Mode("ROOTLESS"), runtime.GOOS, f.configDir)
	require.ErrorIs(t, err, pluginmodel.ErrUnknownMode)
}

// TestReaddWithAnotherSignerReplacesTheCopy: re-adding the same manifest
// signed by another trusted key replaces the copy in place, so it is the one
// consent showed; the same signer keeps it.
func TestReaddWithAnotherSignerReplacesTheCopy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	first := f.install("")
	second, err := pluginsign.GenerateKey()
	require.NoError(t, err)
	f.trustKey(&second.PublicKey)
	f.writeSigned(f.src, localManifest(), second)
	staged, err := Stage(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser)
	require.NoError(t, err)
	shown := staged.SignerKeyID
	require.NotEqual(t, first.SignerKeyID, shown)
	dir, err := staged.Commit()
	require.NoError(t, err)
	require.Equal(t, first.Dir, dir)
	require.Equal(t, shown, staged.SignerKeyID, "the copy in place is the one consent showed, signer included")
	again, err := f.verify(pluginmodel.DefaultInstance, first.ManifestSHA256)
	require.NoError(t, err)
	require.Equal(t, shown, again.SignerKeyID)
	require.Equal(t, []string{first.ManifestSHA256}, entries(t, filepath.Dir(first.Dir)), "nothing left aside")

	// Re-adding with the same signer keeps the copy.
	kept := f.install("")
	require.Equal(t, shown, kept.SignerKeyID)
}

// TestServiceModeLocations: in service mode the plugin root and the trust
// store sit side by side in one root-owned base per OS, never in the config
// directory; in same-user mode both are in the config directory.
func TestServiceModeLocations(t *testing.T) {
	t.Parallel()
	for goos, want := range map[string][2]string{
		"linux":  {"/opt/basalt/plugins", "/opt/basalt/plugin-trust"},
		"darwin": {"/Library/Basalt/plugins", "/Library/Basalt/plugin-trust"},
	} {
		root, err := Root(pluginmodel.ModeService, goos, "/etc/basalt")
		require.NoError(t, err)
		require.Equal(t, want[0], root, goos)
		dir, err := TrustDir(pluginmodel.ModeService, goos, "/etc/basalt")
		require.NoError(t, err)
		require.Equal(t, want[1], dir, goos)
		require.Equal(t, filepath.Dir(root), filepath.Dir(dir), "side by side")
		trust, err := NewTrustStore(testFiles, pluginmodel.ModeService, goos, "/etc/basalt")
		require.NoError(t, err)
		require.Equal(t, want[1], trust.Dir())
		require.Equal(t, uint32(pluginmodel.RootUID), trust.owner)
	}
	root, err := Root(pluginmodel.ModeSameUser, "darwin", "/home/me/.config/basalt")
	require.NoError(t, err)
	require.Equal(t, "/home/me/.config/basalt/plugins", root)
	dir, err := TrustDir("", "linux", "/home/me/.config/basalt")
	require.NoError(t, err)
	require.Equal(t, "/home/me/.config/basalt/plugin-trust", dir)
	_, err = TrustDir(pluginmodel.Mode("ROOTLESS"), "linux", "/x")
	require.ErrorIs(t, err, pluginmodel.ErrUnknownMode)
	_, err = NewTrustStore(testFiles, pluginmodel.Mode("ROOTLESS"), "linux", "/x")
	require.ErrorIs(t, err, pluginmodel.ErrUnknownMode)
}

// TestTrustUnderEngineOwnedConfigRefused: a trust store under a config
// directory that the engine's OS user owns is refused when root is the
// required owner, as in service mode; the rule makes no exception for the
// config directory. The test's own user stands in for the engine's user.
func TestTrustUnderEngineOwnedConfigRefused(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("the test needs a user other than root")
	}
	f := newFixture(t)
	asRoot := f.trust
	asRoot.owner = pluginmodel.RootUID
	err := asRoot.check()
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Contains(t, ve.Why, "owned by")
	_, _, err = asRoot.Add([]byte("x"))
	require.Error(t, err)
	pemBytes, err := MarshalPublicKey(&f.signer.PublicKey)
	require.NoError(t, err)
	_, _, err = asRoot.Add(pemBytes)
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)

	// The same store with the test's user as the required owner passes.
	require.NoError(t, f.trust.check())
}

// TestMissingTrustStoreChecksExistingParents: with no trust store and no
// base directory yet, verification checks the directories that exist and
// trusts only built-in keys.
func TestMissingTrustStoreChecksExistingParents(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	missing := f.trust
	missing.dir = filepath.Join(f.base, "absent", "deeper", pluginmodel.TrustDirName)
	require.NoError(t, missing.check())
	_, err := missing.key("jNZPxNG5htlwfhg4ZgknAA")
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.NoError(t, os.Chmod(f.base, 0o770))
	ve := requireRefused(t, missing.check(), pluginmodel.RefusedNotTrusted)
	require.Equal(t, f.base, ve.File)
	require.NoError(t, os.Chmod(f.base, 0o700))
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
	trust, err := NewTrustStore(testFiles, pluginmodel.ModeService, runtime.GOOS, f.configDir)
	require.NoError(t, err)
	_, err = Verify(f.root, pluginmodel.EntryKey{Name: "acme-ner", Instance: pluginmodel.DefaultInstance}, v.ManifestSHA256, trust, pluginmodel.ModeService)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Contains(t, ve.Why, "owned by")

	// From the root down the owner must be root itself, not just any user
	// root would allow above it.
	_, err = checkStrict(v.Dir, pluginmodel.RootUID)
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)
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

	v, err := installCopy(src, f.root, "", f.trust)
	require.NoError(t, err)
	require.True(t, v.Manifest.Endpoint.IsRemote())
	require.Empty(t, v.Manifest.Files)
	require.ElementsMatch(t, []string{ManifestFile, SignatureFile}, entries(t, v.Dir))
	key := pluginmodel.EntryKey{Name: "acme-cloud", Instance: pluginmodel.DefaultInstance}
	_, err = Verify(f.root, key, v.ManifestSHA256, f.trust, pluginmodel.ModeSameUser)
	require.NoError(t, err)

	extra := filepath.Join(v.Dir, "bin")
	require.NoError(t, os.WriteFile(extra, []byte("x"), 0o644))
	_, err = Verify(f.root, key, v.ManifestSHA256, f.trust, pluginmodel.ModeSameUser)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, extra, ve.File)
	require.NoError(t, os.Remove(extra))

	// The signature still covers every byte.
	other, err := pluginsign.GenerateKey()
	require.NoError(t, err)
	f.writeSigned(src, []byte(remoteManifest), other)
	_, err = installCopy(src, f.root, "second", f.trust)
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)
}

// TestPluginhostInstancesAreSeparate: two instances of one plugin get two copies, and
// changing or removing one does not affect the other.
func TestPluginhostInstancesAreSeparate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a := f.install(pluginmodel.DefaultInstance)
	b := f.install("client_x")
	require.NotEqual(t, a.Dir, b.Dir)
	require.Equal(t, a.ManifestSHA256, b.ManifestSHA256)
	require.Equal(t, filepath.Join(f.root, "acme-ner", "client_x", b.ManifestSHA256), b.Dir)

	require.NoError(t, os.WriteFile(filepath.Join(b.Dir, "model", "weights.bin"), []byte("changed"), 0o644))
	_, err := f.verify("client_x", b.ManifestSHA256)
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	_, err = f.verify(pluginmodel.DefaultInstance, a.ManifestSHA256)
	require.NoError(t, err, "a change to one instance leaves the other intact")

	require.NoError(t, os.RemoveAll(filepath.Join(f.root, "acme-ner", "client_x")))
	_, err = f.verify(pluginmodel.DefaultInstance, a.ManifestSHA256)
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
	_, err := f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
	requireRefused(t, err, pluginmodel.RefusedNotTrusted)

	again := f.install("")
	require.Equal(t, v.Dir, again.Dir)
	_, err = f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
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
	_, err := f.verify(pluginmodel.DefaultInstance, other)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Contains(t, ve.Why, "manifestSha256")
	require.NoError(t, os.Rename(filepath.Join(filepath.Dir(v.Dir), other), v.Dir))

	for _, bad := range []string{"", "ABC", "../x", strings.Repeat("a", 63)} {
		_, err = f.verify(pluginmodel.DefaultInstance, bad)
		requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	}
	for _, inst := range []string{"", "../x", "Client", "x/y"} {
		_, err = f.verify(inst, v.ManifestSHA256)
		requireRefused(t, err, pluginmodel.RefusedBadManifest)
	}
	_, err = Verify(f.root, pluginmodel.EntryKey{Name: "../acme-ner", Instance: pluginmodel.DefaultInstance}, v.ManifestSHA256, f.trust, pluginmodel.ModeSameUser)
	requireRefused(t, err, pluginmodel.RefusedBadManifest)
	_, err = Verify(f.root, pluginmodel.EntryKey{Name: "acme-ner", Instance: pluginmodel.DefaultInstance}, v.ManifestSHA256, f.trust, pluginmodel.Mode("ROOTLESS"))
	require.ErrorIs(t, err, pluginmodel.ErrUnknownMode)
}
