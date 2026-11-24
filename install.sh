#!/bin/sh
# Install BasaltDB binaries from GitHub Releases.
# POSIX sh. BasaltDB is open source under Apache-2.0.
set -eu

# One-line change if the GitHub repo is transferred to a new org.
BASALTDB_REPO="${BASALTDB_REPO:-BasaltDBHq/BasaltDB}"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-}"

usage() {
	cat <<'EOF'
usage: install.sh [latest|nightly|vX.Y.Z]
  VERSION         latest (default; includes prereleases), nightly, or a v* tag
  PREFIX          install dir (default: /usr/local/bin if writable, else ~/.local/bin)
  BASALTDB_REPO   owner/name (default: BasaltDBHq/BasaltDB)
EOF
}

os_name() {
	u=$(uname -s | tr '[:upper:]' '[:lower:]')
	case "$u" in
	linux) echo linux ;;
	darwin) echo darwin ;;
	*)
		echo "install.sh: unsupported OS $u" >&2
		return 1
		;;
	esac
}

arch_name() {
	u=$(uname -m)
	case "$u" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*)
		echo "install.sh: unsupported arch $u" >&2
		return 1
		;;
	esac
}

resolve_tag() {
	want=$1
	case "$want" in
	-h | --help)
		usage
		exit 0
		;;
	--print-platform)
		echo "$(os_name)_$(arch_name)"
		exit 0
		;;
	nightly)
		echo nightly
		return
		;;
	latest | "")
		# Follow the Releases "latest" redirect (no jq).
		# Include prereleases. /releases/latest skips them. Never a release
		# candidate (v*-rc.N): those are for testing, not for installs.
		tag=$(curl -fsSL -H "Accept: application/vnd.github+json" \
			"https://api.github.com/repos/${BASALTDB_REPO}/releases?per_page=10" |
			tr ',' '\n' | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' |
			grep -Ev -- '-rc\.[0-9]+$' | head -n 1)
		if [ -z "$tag" ]; then
			echo "install.sh: could not resolve latest release (GitHub API unavailable, or no v* tag visible)" >&2
			echo "install.sh: build from source instead: https://github.com/BasaltDBHq/BasaltDB/blob/master/docs/install.md" >&2
			return 1
		fi
		echo "$tag"
		return
		;;
	v*)
		echo "$want"
		return
		;;
	*)
		echo "install.sh: VERSION must be latest, nightly, or v*" >&2
		return 1
		;;
	esac
}

# GoReleaser {{ .Version }} is the git tag with a leading v stripped.
# archives.name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
# so a tag such as v0.0.1-alpha → basaltdb_0.0.1-alpha_linux_amd64.tar.gz
archive_version() {
	tag=$1
	if [ "$tag" = nightly ]; then
		echo nightly
		return
	fi
	echo "${tag#v}"
}

archive_name() {
	tag=$1
	os=$2
	arch=$3
	ver=$(archive_version "$tag")
	echo "basaltdb_${ver}_${os}_${arch}.tar.gz"
}

checksum_ok() {
	sums=$1
	file=$2
	if command -v sha256sum >/dev/null 2>&1; then
		grep " ${file}$" "$sums" | sha256sum -c -
		return
	fi
	if command -v shasum >/dev/null 2>&1; then
		grep " ${file}$" "$sums" | shasum -a 256 -c -
		return
	fi
	echo "install.sh: need sha256sum or shasum" >&2
	return 1
}

pick_prefix() {
	if [ -n "$PREFIX" ]; then
		echo "$PREFIX"
		return
	fi
	if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
		echo /usr/local/bin
		return
	fi
	echo "${HOME}/.local/bin"
}

need_sudo() {
	dest=$1
	if [ -w "$dest" ]; then
		return 1
	fi
	return 0
}

main() {
	if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] || [ "${1:-}" = "--print-platform" ]; then
		resolve_tag "$1"
		return
	fi
	if [ "${1:-}" = "--print-archive-name" ]; then
		tag=${2:-}
		case "$tag" in
		nightly | v*) ;;
		*)
			echo "install.sh: --print-archive-name needs nightly or a v* tag" >&2
			return 1
			;;
		esac
		archive_name "$tag" "$(os_name)" "$(arch_name)"
		return
	fi
	if [ -n "${1:-}" ]; then
		VERSION=$1
	fi

	os=$(os_name)
	arch=$(arch_name)
	tag=$(resolve_tag "$VERSION")
	name=$(archive_name "$tag" "$os" "$arch")
	base="https://github.com/${BASALTDB_REPO}/releases/download/${tag}"

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT

	echo "install.sh: ${tag} ${os}/${arch}" >&2
	curl -fsSL -o "${tmp}/${name}" "${base}/${name}"
	curl -fsSL -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS"
	(
		cd "$tmp"
		checksum_ok SHA256SUMS "$name"
	)
	tar -xzf "${tmp}/${name}" -C "$tmp"

	dest=$(pick_prefix)
	mkdir -p "$dest"
	install_cmd="install -m 0755"
	if need_sudo "$dest"; then
		if ! command -v sudo >/dev/null 2>&1; then
			echo "install.sh: $dest is not writable and sudo is not available; set PREFIX" >&2
			return 1
		fi
		echo "install.sh: $dest needs privileges, using sudo" >&2
		install_cmd="sudo install -m 0755"
		sudo mkdir -p "$dest"
	fi

	for bin in basalt; do
		if [ ! -f "${tmp}/${bin}" ]; then
			echo "install.sh: missing $bin in archive" >&2
			return 1
		fi
		$install_cmd "${tmp}/${bin}" "${dest}/${bin}"
	done
	echo "install.sh: installed to $dest" >&2
	"${dest}/basalt" version
}

main "$@"
