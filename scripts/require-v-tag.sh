#!/bin/sh
# Exit 0 only for a leading-v release tag (e.g. v0.0.1-alpha). Refuses nightly, latest, empty, and tags without v.
# Sourced by publish scripts; also executable for tests.
set -eu

require_v_tag() {
	case "${1:-}" in
	v[0-9]*)
		return 0
		;;
	esac
	echo "require-v-tag: refusing ${1:-empty} (need a v* tag)" >&2
	return 1
}

if [ "${0##*/}" = "require-v-tag.sh" ]; then
	require_v_tag "${1:-}"
fi
