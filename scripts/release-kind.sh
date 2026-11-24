#!/bin/sh
# Classify a GitHub Actions event+ref for BasaltDB release policy.
#   rc       — v<semver>-rc.<N> tag push (N digits only); build, end-to-end
#              test, then a GitHub prerelease. No Homebrew, npm or MCP registry.
#   tag      — any other v* tag push (a stable release); published only when a
#              release candidate on the same commit passed (scripts/rc-gate.sh)
#   snapshot — build/test/Actions artifacts only; never publish
#   ignore   — do not run release or publish jobs
#
# Usage: release-kind.sh <event_name> <ref>
set -eu

if [ $# -ne 2 ]; then
	echo "usage: release-kind.sh <event_name> <ref>" >&2
	exit 2
fi

event=$1
ref=$2

case "$event" in
push)
	case "$ref" in
	refs/tags/v[0-9]*-rc.[0-9]*)
		n=${ref##*-rc.}
		case "$n" in
		*[!0-9]*) echo tag ;;
		*) echo rc ;;
		esac
		exit 0
		;;
	refs/tags/v*)
		echo tag
		exit 0
		;;
	refs/tags/*)
		echo ignore
		exit 0
		;;
	refs/heads/*)
		echo snapshot
		exit 0
		;;
	esac
	echo ignore
	exit 0
	;;
pull_request)
	echo snapshot
	exit 0
	;;
workflow_dispatch)
	echo ignore
	exit 0
	;;
esac

echo ignore
