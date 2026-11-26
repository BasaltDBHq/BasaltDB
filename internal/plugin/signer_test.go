package plugin

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// pluginhostApproval is the option of an entry that requires approval.
var pluginhostApproval = RequireApproval(true)

// unsigned removes the .sig from the fixture's source.
func (f *fixture) unsigned() {
	f.t.Helper()
	require.NoError(f.t, os.Remove(filepath.Join(f.src, SignatureFile)))
}

// verifyWith verifies the default instance's copy with opts.
func (f *fixture) verifyWith(manifestSHA string, trust TrustStore, opts ...Option) (pluginmodel.Verified, error) {
	return Verify(f.root, pluginmodel.EntryKey{Name: "acme-ner", Instance: pluginmodel.DefaultInstance}, manifestSHA, trust, pluginmodel.ModeSameUser, opts...)
}

// builtIn is the fixture's trust store with publisher as its one built-in
// key, the seam TestEmbeddedKeys uses: no publisher key is built in yet.
func (f *fixture) builtIn(publisher *ecdsa.PrivateKey) (TrustStore, string) {
	f.t.Helper()
	id, err := KeyID(&publisher.PublicKey)
	require.NoError(f.t, err)
	trust := f.trust
	trust.embedded = map[string]*ecdsa.PublicKey{id: &publisher.PublicKey}
	return trust, id
}

// TestUnsignedStagesWhenApprovalRequired: with approval required a copy with
// no .sig stages, commits and verifies, its signer UNKNOWN with no key id,
// and the copy holds no .sig.
func TestUnsignedStagesWhenApprovalRequired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.unsigned()

	s, err := Stage(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerUnknown, s.Signer)
	require.Empty(t, s.SignerKeyID)
	dir, err := s.Commit()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{ManifestFile, "bin", "model"}, entries(t, dir), "no .sig is made up")

	v, err := f.verifyWith(s.ManifestSHA256, f.trust, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerUnknown, v.Signer)
	require.Empty(t, v.SignerKeyID)
	require.Equal(t, dir, v.Dir)

	// Installing it again keeps the copy.
	again, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, dir, again.Dir)

	// A remote plugin too.
	g := newFixture(t)
	require.NoError(t, os.RemoveAll(g.src))
	require.NoError(t, os.MkdirAll(g.src, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(g.src, ManifestFile), []byte(remoteManifest), 0o644))
	rv, err := installCopy(g.src, g.root, "", g.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerUnknown, rv.Signer)
	require.Equal(t, []string{ManifestFile}, entries(t, rv.Dir))
	_, err = Verify(g.root, pluginmodel.EntryKey{Name: "acme-cloud", Instance: pluginmodel.DefaultInstance}, rv.ManifestSHA256, g.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
}

// TestUnknownKeyIsUnknown: with approval required a .sig by a key the engine
// does not have built in is UNKNOWN with no key id, whether or not the key is
// in the trust store and whether or not it verifies; so is a .sig that fails
// its schema. Without approval the trust store decides as before.
func TestUnknownKeyIsUnknown(t *testing.T) {
	t.Parallel()
	stranger, err := GenerateKey()
	require.NoError(t, err)

	cases := map[string]func(f *fixture){
		"key in the trust store": func(*fixture) {},
		"key nowhere":            func(f *fixture) { f.writeSigned(f.src, localManifest(), stranger) },
		"key in the trust store, does not verify": func(f *fixture) {
			other := localManifest()
			other[len(other)-2] = ' '
			sig, err := SignManifest(other, f.signer)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(f.src, SignatureFile), sig, 0o644))
		},
		"fails its schema": func(f *fixture) {
			require.NoError(t, os.WriteFile(filepath.Join(f.src, SignatureFile), []byte(`{"keyId":"made-up"}`), 0o644))
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			prepare(f)
			v, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			require.NoError(t, err)
			require.Equal(t, pluginmodel.SignerUnknown, v.Signer)
			require.Empty(t, v.SignerKeyID, "a key id that cannot be checked is not reported")
			require.Contains(t, entries(t, v.Dir), SignatureFile, "the .sig read is the .sig kept")

			got, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			require.NoError(t, err)
			require.Equal(t, pluginmodel.SignerUnknown, got.Signer)
			require.Empty(t, got.SignerKeyID)
		})
	}

	// Without approval a trusted key is reported as before; it is not built
	// in, so it is not KNOWN.
	f := newFixture(t)
	v := f.install("")
	id, err := KeyID(&f.signer.PublicKey)
	require.NoError(t, err)
	require.Equal(t, id, v.SignerKeyID)
	require.Equal(t, pluginmodel.SignerUnknown, v.Signer)
}

// TestKnownSignerIsKnown: a .sig by a built-in key that verifies is KNOWN with
// its key id, with approval required or not.
func TestKnownSignerIsKnown(t *testing.T) {
	t.Parallel()
	for name, opts := range map[string][]Option{"approval": {pluginhostApproval}, "no approval": nil, "approval off": {RequireApproval(false)}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			publisher, err := GenerateKey()
			require.NoError(t, err)
			trust, id := f.builtIn(publisher)
			f.writeSigned(f.src, localManifest(), publisher)
			v, err := installCopy(f.src, f.root, "", trust, pluginmodel.ModeSameUser, opts...)
			require.NoError(t, err)
			require.Equal(t, pluginmodel.SignerKnown, v.Signer)
			require.Equal(t, id, v.SignerKeyID)
			got, err := f.verifyWith(v.ManifestSHA256, trust, opts...)
			require.NoError(t, err)
			require.Equal(t, pluginmodel.SignerKnown, got.Signer)
			require.Equal(t, id, got.SignerKeyID)
		})
	}
}

// TestBadKnownSignatureRefused: a .sig that names a built-in key and does not
// verify, or names one and fails its schema, is refused at Stage and at
// Verify, with approval required or not.
func TestBadKnownSignatureRefused(t *testing.T) {
	t.Parallel()
	type badSig func(t *testing.T, publisher *ecdsa.PrivateKey, id string) []byte
	bad := map[string]badSig{
		"signs another manifest": func(t *testing.T, publisher *ecdsa.PrivateKey, _ string) []byte {
			other := localManifest()
			other[len(other)-2] = ' '
			sig, err := SignManifest(other, publisher)
			require.NoError(t, err)
			return sig
		},
		"fails its schema": func(t *testing.T, publisher *ecdsa.PrivateKey, _ string) []byte {
			sig, err := SignManifest(localManifest(), publisher)
			require.NoError(t, err)
			var s signatureFile
			require.NoError(t, json.Unmarshal(sig, &s))
			s.Alg = "ES384"
			b, err := json.Marshal(s)
			require.NoError(t, err)
			return b
		},
		"names it twice": func(t *testing.T, _ *ecdsa.PrivateKey, id string) []byte {
			return []byte(`{"keyId":"` + id + `","keyId":"AAAAAAAAAAAAAAAAAAAAAA","alg":"ES256","sig":"x"}`)
		},
		"names it escaped": func(t *testing.T, _ *ecdsa.PrivateKey, id string) []byte {
			return []byte(`{"keyId":"\u00` + strings.ToLower(hexByte(id[0])) + id[1:] + `","alg":"ES256","sig":"x"}`)
		},
	}
	options := map[string][]Option{"approval": {pluginhostApproval}, "no approval": nil}
	for name, makeSig := range bad {
		for optName, opts := range options {
			t.Run(name+"/"+optName, func(t *testing.T) {
				t.Parallel()
				publisher, err := GenerateKey()
				require.NoError(t, err)

				// At Stage.
				f := newFixture(t)
				trust, id := f.builtIn(publisher)
				f.writeSigned(f.src, localManifest(), publisher)
				require.NoError(t, os.WriteFile(filepath.Join(f.src, SignatureFile), makeSig(t, publisher, id), 0o644))
				_, err = installCopy(f.src, f.root, "", trust, pluginmodel.ModeSameUser, opts...)
				ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
				require.Equal(t, filepath.Join(f.src, SignatureFile), ve.File)
				require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner", pluginmodel.DefaultInstance)), "a refused add leaves no copy")

				// At Verify: a good copy whose .sig is swapped afterwards.
				g := newFixture(t)
				gtrust, gid := g.builtIn(publisher)
				g.writeSigned(g.src, localManifest(), publisher)
				v, err := installCopy(g.src, g.root, "", gtrust, pluginmodel.ModeSameUser, opts...)
				require.NoError(t, err)
				require.Equal(t, pluginmodel.SignerKnown, v.Signer)
				sigPath := filepath.Join(v.Dir, SignatureFile)
				require.NoError(t, os.WriteFile(sigPath, makeSig(t, publisher, gid), 0o644))
				_, err = g.verifyWith(v.ManifestSHA256, gtrust, opts...)
				ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
				require.Equal(t, sigPath, ve.File)
			})
		}
	}
}

// hexByte is c as two hex digits.
func hexByte(c byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[c>>4], digits[c&0xf]})
}

// TestUnsignedStillRefusedWithoutApproval: without approval a copy with no
// .sig is refused at add, and an unsigned copy installed for an entry that
// requires approval is refused at start for one that does not.
func TestUnsignedStillRefusedWithoutApproval(t *testing.T) {
	t.Parallel()
	for name, opts := range map[string][]Option{"no option": nil, "option off": {RequireApproval(false)}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.unsigned()
			_, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, opts...)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, filepath.Join(f.src, SignatureFile), ve.File)
			require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner", pluginmodel.DefaultInstance)))

			v, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			require.NoError(t, err)
			_, err = f.verifyWith(v.ManifestSHA256, f.trust, opts...)
			ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, filepath.Join(v.Dir, SignatureFile), ve.File)

			// A copy signed by a key the trust store lacks is refused too.
			g := newFixture(t)
			stranger, err := GenerateKey()
			require.NoError(t, err)
			g.writeSigned(g.src, localManifest(), stranger)
			_, err = installCopy(g.src, g.root, "", g.trust, pluginmodel.ModeSameUser, opts...)
			ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Contains(t, ve.Why, "not trusted")
		})
	}
}

// TestApprovalKeepsEveryOtherCheck: with approval required an unsigned copy
// passes, and the same copy with one thing broken is refused exactly as
// before: a file's hash, the path rule, a file the manifest does not list,
// a missing file, a manifest rule, the entry's manifestSha256, and the trust
// store's path rule.
func TestApprovalKeepsEveryOtherCheck(t *testing.T) {
	t.Parallel()
	type check func(t *testing.T, f *fixture, v pluginmodel.Verified)
	cases := map[string]check{
		"file hash at verify": func(t *testing.T, f *fixture, v pluginmodel.Verified) {
			bin := filepath.Join(v.Dir, "bin", "acme-ner")
			require.NoError(t, os.WriteFile(bin, []byte(strings.Replace(testBinary, "echo", "eCho", 1)), 0o755))
			_, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, bin, ve.File)
			require.Contains(t, ve.Why, "SHA-256")
		},
		"file hash at add": func(t *testing.T, f *fixture, _ pluginmodel.Verified) {
			srcModel := filepath.Join(f.src, "model", "weights.bin")
			require.NoError(t, os.WriteFile(srcModel, []byte("TOP-SECRET-MODEL-WEIGHTz"), 0o644))
			_, err := installCopy(f.src, f.root, "x", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.True(t, strings.HasSuffix(ve.File, filepath.Join("model", "weights.bin")), ve.File)
			require.Contains(t, ve.Why, "SHA-256")
			require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner", "x")))
		},
		"path rule": func(t *testing.T, f *fixture, v pluginmodel.Verified) {
			p := filepath.Join(v.Dir, "bin")
			require.NoError(t, os.Chmod(p, 0o775))
			_, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, p, ve.File)
			require.Contains(t, ve.Why, "written by group or others")
			require.NotNil(t, ve.Path)
		},
		"trust store path rule": func(t *testing.T, f *fixture, v pluginmodel.Verified) {
			p := f.trust.Dir()
			require.NoError(t, os.Chmod(p, 0o757))
			_, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, p, ve.File)
			require.Contains(t, ve.Why, "written by group or others")
		},
		"symlink in source": func(t *testing.T, f *fixture, _ pluginmodel.Verified) {
			model := filepath.Join(f.src, "model", "weights.bin")
			elsewhere := filepath.Join(f.base, "weights.bin")
			require.NoError(t, os.Rename(model, elsewhere))
			require.NoError(t, os.Symlink(elsewhere, model))
			_, err := installCopy(f.src, f.root, "x", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, model, ve.File)
			require.Contains(t, ve.Why, "symlink")
		},
		"symlink as the .sig": func(t *testing.T, f *fixture, _ pluginmodel.Verified) {
			sig := filepath.Join(f.src, SignatureFile)
			require.NoError(t, os.WriteFile(filepath.Join(f.base, "elsewhere.sig"), []byte("{}"), 0o644))
			require.NoError(t, os.Symlink(filepath.Join(f.base, "elsewhere.sig"), sig))
			_, err := installCopy(f.src, f.root, "x", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, sig, ve.File)
			require.Contains(t, ve.Why, "symlink")
		},
		"symlink as the installed .sig": func(t *testing.T, f *fixture, v pluginmodel.Verified) {
			sig := filepath.Join(v.Dir, SignatureFile)
			require.NoError(t, os.WriteFile(filepath.Join(f.base, "elsewhere.sig"), []byte("{}"), 0o644))
			require.NoError(t, os.Symlink(filepath.Join(f.base, "elsewhere.sig"), sig))
			_, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, sig, ve.File)
		},
		"extra file in copy": func(t *testing.T, f *fixture, v pluginmodel.Verified) {
			extra := filepath.Join(v.Dir, "bin", "helper")
			require.NoError(t, os.WriteFile(extra, []byte("x"), 0o644))
			_, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, extra, ve.File)
			require.Contains(t, ve.Why, "not in the manifest's files")
		},
		"missing file in copy": func(t *testing.T, f *fixture, v pluginmodel.Verified) {
			p := filepath.Join(v.Dir, "model", "weights.bin")
			require.NoError(t, os.Remove(p))
			_, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, p, ve.File)
			require.Contains(t, ve.Why, "missing")
		},
		"manifest rule": func(t *testing.T, f *fixture, _ pluginmodel.Verified) {
			m := strings.Replace(string(localManifest()), `"version": "1.4.0"`, `"version": "one"`, 1)
			require.NoError(t, os.WriteFile(filepath.Join(f.src, ManifestFile), []byte(m), 0o644))
			_, err := installCopy(f.src, f.root, "x", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedBadManifest)
			require.Equal(t, filepath.Join(f.src, ManifestFile), ve.File)
		},
		"files names the .sig": func(t *testing.T, f *fixture, _ pluginmodel.Verified) {
			m := strings.Replace(string(localManifest()), `"files": {`, `"files": { "basalt-plugin.json.sig": "`+sha("x")+`",`, 1)
			require.NoError(t, os.WriteFile(filepath.Join(f.src, ManifestFile), []byte(m), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(f.src, SignatureFile), []byte("x"), 0o644))
			_, err := installCopy(f.src, f.root, "x", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedBadManifest)
			require.Equal(t, whyFilesNameManifest, ve.Why)
		},
		"entry's manifestSha256": func(t *testing.T, f *fixture, v pluginmodel.Verified) {
			// Another manifest put in place of the copy's.
			m := strings.Replace(string(localManifest()), `"version": "1.4.0"`, `"version": "1.4.1"`, 1)
			p := filepath.Join(v.Dir, ManifestFile)
			require.NoError(t, os.WriteFile(p, []byte(m), 0o644))
			_, err := f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
			require.Equal(t, p, ve.File)
			require.Contains(t, ve.Why, "manifestSha256")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.unsigned()
			v, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
			require.NoError(t, err)
			_, err = f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
			require.NoError(t, err, "the unsigned copy passes before it is broken")
			run(t, f, v)
		})
	}
}

// TestCommitKeepsOnlyTheSameSigner: re-adding a copy whose manifest is
// already in place keeps that copy only when its signer is the staged
// one's, so a KNOWN copy is not kept for an unsigned add, nor the reverse.
func TestCommitKeepsOnlyTheSameSigner(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	publisher, err := GenerateKey()
	require.NoError(t, err)
	trust, id := f.builtIn(publisher)
	f.writeSigned(f.src, localManifest(), publisher)
	known, err := installCopy(f.src, f.root, "", trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerKnown, known.Signer)

	f.unsigned()
	unknown, err := installCopy(f.src, f.root, "", trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, known.Dir, unknown.Dir)
	require.Equal(t, pluginmodel.SignerUnknown, unknown.Signer)
	require.NotContains(t, entries(t, unknown.Dir), SignatureFile, "the unsigned copy replaced the signed one")
	got, err := f.verifyWith(unknown.ManifestSHA256, trust, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerUnknown, got.Signer)

	f.writeSigned(f.src, localManifest(), publisher)
	again, err := installCopy(f.src, f.root, "", trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerKnown, again.Signer)
	require.Equal(t, id, again.SignerKeyID)
	got, err = f.verifyWith(again.ManifestSHA256, trust, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerKnown, got.Signer)
}

// TestCommitKeepsOnlyTheSameSignatureFile: with approval two UNKNOWN copies
// of one manifest can differ in their .sig; the copy in place is always the
// staged one's.
func TestCommitKeepsOnlyTheSameSignatureFile(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, pluginmodel.SignerUnknown, v.Signer)
	require.Contains(t, entries(t, v.Dir), SignatureFile)

	f.unsigned()
	u, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	require.Equal(t, v.Dir, u.Dir)
	require.NotContains(t, entries(t, u.Dir), SignatureFile, "the unsigned copy replaced the one with a .sig")

	stranger, err := GenerateKey()
	require.NoError(t, err)
	f.writeSigned(f.src, localManifest(), stranger)
	s, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)
	want, err := os.ReadFile(filepath.Join(f.src, SignatureFile))
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(s.Dir, SignatureFile))
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// TestSignatureDirectoryRefused: with approval a .sig that is a directory is
// refused, in the source and in the copy, never taken as unsigned.
func TestSignatureDirectoryRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.unsigned()
	v, err := installCopy(f.src, f.root, "", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	require.NoError(t, err)

	inCopy := filepath.Join(v.Dir, SignatureFile)
	require.NoError(t, os.Mkdir(inCopy, 0o755))
	_, err = f.verifyWith(v.ManifestSHA256, f.trust, pluginhostApproval)
	ve := requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.True(t, strings.HasPrefix(ve.File, inCopy), ve.File)

	inSource := filepath.Join(f.src, SignatureFile)
	require.NoError(t, os.Mkdir(inSource, 0o755))
	_, err = installCopy(f.src, f.root, "x", f.trust, pluginmodel.ModeSameUser, pluginhostApproval)
	ve = requireRefused(t, err, pluginmodel.RefusedNotTrusted)
	require.Equal(t, inSource, ve.File)
}
