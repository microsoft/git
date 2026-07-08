#!/bin/sh
#
# Promote a microsoft/git release into the microsoft/winget-pkgs repo.
#
# Usage:
#   .github/release-winget.sh [<TAG_NAME>]
#
# If TAG_NAME is omitted, the latest microsoft/git release is used.
#
# Prerequisites:
#   - Runs on Windows (the winget authoring tool wingetcreate.exe is
#     Windows-only). Use Git for Windows' bash, an MSYS2 shell, WSL
#     Bash, or an equivalent.
#   - `gh` authenticated (via `gh auth login`) as a user with (a) push
#     access to a personal fork of microsoft/winget-pkgs and (b)
#     permission to open a pull request against microsoft/winget-pkgs.
#     wingetcreate will create the fork on the fly if it does not
#     already exist.
#   - `curl` and `jq` on PATH.
#
# Given a release tag on microsoft/git (e.g. v2.54.0.vfs.0.4), the
# script downloads wingetcreate, converts the tag to winget's dotted
# numeric version format (v2.54.0.vfs.0.4 -> 2.54.0.0.4), fetches the
# four installer URLs (x64 machine, x64 user, arm64 machine, arm64
# user) from the corresponding GitHub release, builds an updated
# manifest for the Microsoft.Git package, syncs the operator's fork
# of microsoft/winget-pkgs with upstream, and submits the manifest
# via a pull request against microsoft/winget-pkgs.

set -eu

die () {
	echo "error: $*" >&2
	exit 1
}

case "$(uname -s)" in
MINGW*|MSYS*|CYGWIN*) ;; # okay
Linux)
	# Could be WSL
	test -f /proc/sys/fs/binfmt_misc/WSLInterop ||
	die "this script requires Windows"
	;;
*)
	die "this script requires Git for Windows / MSYS:" \
		"wingetcreate is a Windows-only tool"
	;;
esac

TAG_NAME=${1-}
if [ -z "$TAG_NAME" ]; then
	echo "==> No tag given; resolving latest microsoft/git release"
	TAG_NAME=$(gh release view -R microsoft/git \
		--json tagName --jq .tagName)
	test -n "$TAG_NAME" || die "could not determine latest release tag"
fi

echo "==> Tag:       $TAG_NAME"

# Elide the leading 'v' and the 'vfs.' segment:
# v2.54.0.vfs.0.4 -> 2.54.0.0.4
version=$(printf '%s' "${TAG_NAME#v}" | sed 's/vfs\.//')
echo "==> Version:   $version"

echo "==> Fetching release metadata"
release_json=$(gh api \
	-H "Accept: application/vnd.github+json" \
	-H "X-GitHub-Api-Version: 2022-11-28" \
	"repos/microsoft/git/releases/tags/$TAG_NAME")

pick_asset () {
	# $1: jq regex to match the asset name.
	jq -n -r --argjson r "$release_json" --arg pat "$1" '
		[ $r.assets[] | select(.name | test($pat)) ] as $m
		| if $m | length == 0 then
			error("no asset matches pattern \($pat)")
		  elif $m | length > 1 then
			error("multiple assets match \($pat)")
		  else $m[0] end'
}

x64_asset=$(pick_asset '64-bit\.exe$')
arm64_asset=$(pick_asset 'arm64\.exe$')

# wingetcreate downloads the installer to compute its hash. Use the
# public browser URL for anonymous access rather than the API URL.
x64_url=$(printf '%s' "$x64_asset" | jq -r .browser_download_url)
arm64_url=$(printf '%s' "$arm64_asset" | jq -r .browser_download_url)

echo "==> x64 asset: $(printf '%s' "$x64_asset" | jq -r .name)"
echo "==> arm64:     $(printf '%s' "$arm64_asset" | jq -r .name)"

workdir=$(mktemp -d)
success=0
cleanup () {
	if [ "$success" = 1 ]; then
		rm -rf "$workdir"
	else
		echo "==> Workdir retained for inspection: $workdir" >&2
	fi
}
trap cleanup EXIT

cd "$workdir"
echo "==> Working in $workdir"

echo "==> Downloading wingetcreate"
test -x wingetcreate.exe || {
	curl -fsSL https://aka.ms/wingetcreate/latest -o wingetcreate.exe &&
	chmod +x wingetcreate.exe
} || die "Could not initialize wingetcreate.exe"

# wingetcreate reads its GitHub token from this env var; hand it the
# operator's own gh session token so no PAT needs to be stashed.
WINGET_CREATE_GITHUB_TOKEN=$(gh auth token)
export WINGET_CREATE_GITHUB_TOKEN

echo "==> Building manifest for Microsoft.Git $version"
./wingetcreate.exe update Microsoft.Git \
	-v "$version" \
	-o . \
	-u "$x64_url|x64|machine" \
	   "$x64_url|x64|user" \
	   "$arm64_url|arm64|machine" \
	   "$arm64_url|arm64|user"

# wingetcreate submit pushes to the operator's personal fork of
# microsoft/winget-pkgs and opens a PR from there. A stale fork makes
# submit fail with "The forked repository could not be synced with
# the upstream commits"; sync it first. If no fork exists yet (404),
# wingetcreate will create a fresh one at submit time, so treat that
# as fine.
user=$(gh api user --jq .login)
echo "==> Syncing $user/winget-pkgs fork with upstream"
sync_err=$(mktemp)
if gh api --silent --method POST \
		"repos/$user/winget-pkgs/merge-upstream" \
		-f branch=master 2>"$sync_err"; then
	echo "==> Fork sync: OK"
elif grep -q '404' "$sync_err"; then
	echo "==> Fork sync: no fork; will create on submit"
else
	cat "$sync_err" >&2
	rm -f "$sync_err"
	die "fork sync failed"
fi
rm -f "$sync_err"

manifest_dir="$PWD/manifests/m/Microsoft/Git/$version"
echo "==> Submitting $manifest_dir"
submit_out=$(./wingetcreate.exe submit "$manifest_dir")
echo "$submit_out"

pr_url=$(printf '%s\n' "$submit_out" |
	grep -oE 'https://github\.com/microsoft/winget-pkgs/pull/[^ ]+' ||
	true)
test -z "$pr_url" || echo "==> Created:   $pr_url"

success=1
