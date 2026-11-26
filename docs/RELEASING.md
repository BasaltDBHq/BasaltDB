# Releasing BasaltDB

BasaltDB is open source under Apache-2.0.

## Who creates tags

The **release owner** creates and pushes git tags by hand, once per milestone cut. Nobody else tags: not CI, not the cloud agent, not a bot.

CI **never** runs `git tag`, `git push --tags`, or `gh release create` in a way that would create a tag (the release candidate's `gh release create` uses `--verify-tag`: the tag must already exist). Branch and PR pushes build snapshot archives as GitHub Actions artifacts only. Registry publishing and GitHub Releases exist only for `v*` tags that a human already pushed.

## Naming

Tags are semver with a leading `v`. Release tags **MUST** start with `v` (e.g. `v0.0.1-alpha`): [`.github/workflows/release.yml`](../.github/workflows/release.yml) only triggers on `v*` (`tags: ["v*"]`). A tag such as `0.0.1-alpha` will not cut a GitHub Release.

| Kind | Example | When |
|------|---------|------|
| Release candidate | `v0.1.0-alpha-rc.1`, `v1.0.0-rc.2` | Before every release: the tag to test, then `-rc.<N>`, digits only. Never installed by users. |
| Alpha | `v0.1.0-alpha` | Published only on a commit whose release candidate passed |
| Beta | `v0.2.0-beta.1` | When we say so |
| Stable | `v1.0.0` | No prerelease suffix |

A release candidate is not a version of its own: `v1.0.0-rc.1` is the candidate for `v1.0.0`, and `v0.1.0-alpha-rc.1` the candidate for `v0.1.0-alpha`. The release tag (alpha, beta or stable, "the release" below) and its candidates sit on the same commit.

`go install …@latest` **ignores prereleases**. Once a release exists, pin its tag, for example `@v0.1.0-alpha`. `install.sh` with no argument (`latest`) includes prereleases but never a release candidate; GitHub `/releases/latest` includes neither.

## How to cut a release

A release is two pushes on the same commit: a release candidate, which is built and tested end to end, then the release itself, which publishes only when a candidate of it passed on that commit.

On a machine with push access, after `master` is the commit you want:

1. Run `make check-provider-roots`. It downloads each built-in trust profile's `source` (Supabase's and Amazon RDS's published roots) and compares each with the file the binary embeds. It needs the network and is not part of CI. When it fails, check that the provider only added roots, replace the file under `internal/core/trustprofile/profiles/`, update its `sha256` in the profile and its pin in `internal/core/trustprofile/builtin_test.go`, and merge that first.
2. Make sure `CHANGELOG.md` on that commit has a `## [<version>] - <date>` section for the release (the tag without its `v`, for example `## [0.1.0-alpha] - 2026-11-24`). Its body becomes the release notes; the candidate fails at once without it.
3. Push the release candidate:

```bash
git checkout master
git pull origin master
# NEXT_TAG must start with v and must not already exist, e.g. v0.1.0-alpha.
git tag -a "$NEXT_TAG-rc.1" -m "..."
git push origin "$NEXT_TAG-rc.1"
```

4. Wait for its [Release](../.github/workflows/release.yml) run. It builds and signs the archives, runs the end-to-end test against them on `macos-15` (arm64), `macos-15-intel` and `ubuntu-latest` (jobs `e2e (<runner>)`), and when every leg passes saves those same files as a **draft** GitHub release named after the candidate (only maintainers see drafts, so no user, update check or `install.sh` ever finds one), with the body "Release candidate for `<release>`. Not for general use." No release notes, Homebrew, npm, MCP registry or portal check. `install.sh` never picks a candidate.
   - **Red:** nothing is published. The failed job and step say what broke. Fix it on `master`, then push `-rc.2` (the next `N`) on the new commit and wait again. A flaky leg can be re-run from the Actions page; a re-run that passes counts.
5. Push the release on the same commit:

```bash
git tag -a "$NEXT_TAG" -m "..." "$NEXT_TAG-rc.1^{commit}"   # the candidate's commit
git push origin "$NEXT_TAG"
```

   Its `gate` job (`scripts/rc-gate.sh`) looks for a Release run of `<release>-rc.<N>` on this commit that ended in success with every `e2e` leg green; any green candidate counts, however many red ones the commit also has. Without one the run stops and names the candidate to push. If you pushed the release tag before the candidate's run finished, the gate sees it `in_progress` and refuses: once the candidate is green, re-run the failed jobs of the release tag's run, once. No new tag is needed. Branches play no part: the gate checks the commit. Then the release is built again from that commit and published as described below. It is not a copy of the candidate's files: the version is built into the binary and the signature names the tag, so the files differ from the candidate's only in that.

The release tag's push is the only trigger for a full GitHub Release. The first releases publish to GitHub only: npm, the MCP registry and the Homebrew tap are off until you switch them on (see [Other channels](#other-channels)). The [Release](../.github/workflows/release.yml) workflow then:

1. Builds linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 (`CGO_ENABLED=0`). Windows is not built yet.
2. Attaches tar.gz holding the one `basalt` binary, `SHA256SUMS`, its Sigstore signature `SHA256SUMS.sigstore.json` ([Signed checksums](#signed-checksums)), and `.deb` / `.rpm` / `.apk`. It also attaches `portal.sha256`, a copy of `web/portal.sha256` from the tagged commit (the hashes of the portal pages that release embeds), for `make portal-verify`. Darwin tarballs are `CGO_ENABLED=0` static builds. They are unsigned (no Apple Developer account, codesign, or notarization). After a browser download, clear Gatekeeper quarantine **per binary** the operator verified (`xattr -d com.apple.quarantine ./basalt`), never recursively. CI `macos-smoke` runs those archives on `macos-15-intel` (`uname -m` x86_64) for every run and on `macos-15` (`uname -m` arm64) for pushes to master, the nightly run and manual runs.
3. Marks the GitHub Release as a **prerelease** when the tag has a semver prerelease suffix (`-alpha`, `-beta`). `prerelease: auto` in GoReleaser.

Release notes are the tag's section of [CHANGELOG.md](../CHANGELOG.md), printed by `scripts/release-notes.sh <tag>` and passed with `--release-notes`; GoReleaser never writes notes from git.

### Docs version

The docs site at docs.basaltvault.app has one version per minor release, plus `master`. When a tag starts a new minor line (`v0.1.0`, or its first prerelease such as `v0.1.0-alpha`), cut a docs version the same day in [BasaltDBHq/basaltdb-documentation](https://github.com/BasaltDBHq/basaltdb-documentation):

```bash
npm run cut-version -- 0.1    # add --tag "latest · alpha" while the line is alpha
```

Then open its pull request and merge it. Patches and later prereleases in the same line need no cut; their docs changes go into that repository's latest-release pages. The repository's README describes the cut.

### Reproducible builds

Release artifacts are reproducible: the same tagged commit built with the same Go toolchain (the `toolchain` line in `go.mod`) gives byte-identical archives, packages and `SHA256SUMS` on any machine. [`.goreleaser.yaml`](../.goreleaser.yaml) takes every timestamp from the commit being built, not from the clock:

- the binary's mtime (`mod_timestamp: "{{ .CommitTimestamp }}"`) and `SOURCE_DATE_EPOCH` in the build environment;
- the mtime of every entry in the tar.gz archives and in the `.deb` / `.rpm` / `.apk` packages (`{{ .CommitDate }}`), with archive entries owned by `root:root`;
- `-trimpath`, so no build-machine paths end up in the binary.

To check a release yourself, check out the tag, install the `go.mod` toolchain, and run the same build without publishing; the `SHA256SUMS` should match the one on the release:

```bash
git checkout "$TAG"
BASALT_VERSION="$TAG" RELEASE_KIND=snapshot GITHUB_REPOSITORY=BasaltDBHq/BasaltDB HOMEBREW_TAP_GITHUB_TOKEN= \
  goreleaser release --clean --skip=publish --skip=homebrew --skip=announce --skip=validate --skip=sign
cat dist/SHA256SUMS
```

### Signed checksums

The release job signs `SHA256SUMS` with cosign, keyless ([`.goreleaser.yaml`](../.goreleaser.yaml), `signs`), and attaches the Sigstore bundle as `SHA256SUMS.sigstore.json`. `SHA256SUMS` lists every archive and package and `portal.sha256`, so the one signature covers them all.

- The job has `id-token: write`. cosign trades the job's GitHub OIDC token for a short-lived Fulcio certificate whose identity is `https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>`, signs, and records the signature in the public Rekor log. There is no signing key or secret to manage or rotate.
- `sigstore/cosign-installer` puts `cosign` on the runner. If signing fails, GoReleaser stops before it publishes, so a release is never published unsigned.
- CI snapshot builds and the reproducibility check above pass `--skip=sign`: they have no OIDC token and publish nothing.
- The signature is not part of the reproducible output: each signing run gets a new certificate and log entry, so `SHA256SUMS.sigstore.json` differs from run to run while `SHA256SUMS` stays the same.

How a user checks it is in the [install guide](install.md#check-the-signature).

There is no container image: `basalt` runs next to the agent as a local service, not as a hosted server.

Owner/repo in the workflow and GoReleaser come from `${{ github.repository }}` / `${{ github.repository_owner }}`. Transferring the repo to a new GitHub org does not require a config rewrite. `install.sh` defaults to `BASALTDB_REPO=BasaltDBHq/BasaltDB` (one-line change after a transfer).

Do not force-push tags. Do not create a `nightly` git tag.

## Master / PR (no tag)

Merges and pull requests run **CI** only ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)). They must not publish.

- Actions artifact `basaltdb-snapshot` (archives + packages + `SHA256SUMS`). Snapshot version is `0.0.0-nightly` (archive name only).
- Native archive smoke on `macos-15-intel` (x86_64) for every run, and on `macos-15` (arm64) for pushes to master, the nightly run and manual runs (the arm64 runner's queue is too slow for pull requests).
- No GitHub Release, no git tag, no npm / Homebrew / MCP registry write.

The Release workflow has no `branches`, `pull_request`, or `workflow_dispatch` trigger.

## Event / condition matrix

`scripts/release-kind.sh` (and `make install-sh-check`) encodes the kinds. `rc` saves only a draft GitHub release, after the end-to-end test; `tag` publishes everything, after `scripts/rc-gate.sh` found a passing `rc` on the same commit.

| Event | Ref | Kind | CI snapshot artifacts | Registry / GitHub Release |
|-------|-----|------|------------------------|---------------------------|
| `push` | `refs/heads/master` | snapshot | yes (`ci.yml`) | no |
| `push` | `refs/heads/main` | snapshot | no (CI watches `master` only) | no |
| `push` | other branch | snapshot | no (CI watches `master` + PRs) | no |
| `pull_request` | `refs/pull/N/merge` | snapshot | yes (`ci.yml`) | no |
| `workflow_dispatch` | any | ignore | no | no (not a workflow trigger) |
| `push` | `refs/tags/v0.1.0-alpha-rc.1` | rc | n/a | draft GitHub release only, after the e2e (`release.yml`) |
| `push` | `refs/tags/v0.1.0-alpha` | tag | n/a | **yes**, after the gate (`release.yml`) |
| `push` | `refs/tags/nightly` | ignore | no | no (`v*` filter) |
| `push` | `refs/tags/0.0.1-alpha` | ignore | no | no (must start with `v`) |

Publish scripts (`npm-publish.sh`, `mcp-registry-publish.sh`) also refuse a non-`v*` tag even if invoked by hand. Tests are read-only: they do not log in or push.

## Install after a tag

After a tag, people can install from Homebrew (`brew install basaltdbhq/tap/basaltdb`), a Release archive or package, anonymous [install.sh](../install.sh), or `go install`. The [install guide](install.md) is the user-facing path. Pin the tag (`v0.0.1-alpha.2` below is an example):

```bash
curl -fsSL https://raw.githubusercontent.com/BasaltDBHq/BasaltDB/master/install.sh | sh -s v0.0.1-alpha.2

curl -fsSL -o basaltdb.tgz https://github.com/BasaltDBHq/BasaltDB/releases/download/v0.0.1-alpha.2/basaltdb_0.0.1-alpha.2_linux_amd64.tar.gz
curl -fsSL -O https://github.com/BasaltDBHq/BasaltDB/releases/download/v0.0.1-alpha.2/SHA256SUMS
```

## go install

`go.mod` declares **`github.com/basaltdbhq/basaltdb`**, the lowercase module path for the public repo **`BasaltDBHq/BasaltDB`**.

```bash
# from a clone
CGO_ENABLED=0 go install ./cmd/basalt

CGO_ENABLED=0 go install github.com/basaltdbhq/basaltdb/cmd/basalt@v0.0.1-alpha
```

`@latest` will not pick an alpha tag. Pin the tag, for example `@v0.1.0-alpha`.

Release binaries embed the tag via `-ldflags`. `go install` uses the module version from build info when ldflags did not override it.

## Other channels

A release tag publishes the GitHub Release (binaries, packages, `SHA256SUMS`, `portal.sha256`) using only the default `GITHUB_TOKEN`. Release candidates never publish to the channels below. Every other channel is off by default and is switched on with a repository variable (Settings, Secrets and variables, Actions, Variables). Set the variable to exactly `true`; any other value, or unset, leaves it off. Do it before pushing the tag you want it for: the variables are read when the tag's workflow runs.

| Channel | Variable | Secret it needs | Notes |
|---------|----------|-----------------|-------|
| Homebrew | `PUBLISH_HOMEBREW` | `HOMEBREW_TAP_GITHUB_TOKEN_BASALTDB` (write access to the tap) | Tap defaults to `BasaltDBHq/homebrew-tap`; override with the variables `HOMEBREW_TAP_OWNER` / `HOMEBREW_TAP_NAME`. Install: `brew install basaltdbhq/tap/basaltdb`. |
| npm | `PUBLISH_NPM` | `NPM_TOKEN` | Scope `@basaltdb`, owned by the personal npm account `basaltdb` (unscoped `basaltdb` is a different product). Publishes `@basaltdb/cli` and `@basaltdb/{linux-x64,linux-arm64,darwin-x64,darwin-arm64}` with `--access public`. Prereleases use the dist-tag `alpha`/`beta`/`rc`, not `latest`. |
| MCP registry | `PUBLISH_MCP_REGISTRY` | `MCP_REGISTRY_TOKEN` | `server.json` name and npm `mcpName` are `io.github.basaltdbhq/basaltdb`. Runs after the npm job when npm is on, and alone when npm is off; the registry entry points at the npm package, so that package must already exist. |

With `PUBLISH_NPM` or `PUBLISH_MCP_REGISTRY` on but its secret empty, the script exits 0 and publishes nothing. With `PUBLISH_HOMEBREW` on but no tap token, the release job fails at the formula upload.
