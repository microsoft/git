#!/usr/bin/env bash
# Materialise the build-installers flavour of the Git for Windows SDK.
#
# Performs a partial + bare clone of the given Git SDK repository,
# then runs build-extra's please.sh to sparse-checkout just the
# build-installers subset into the requested SDK output directory.
#
# Environment:
#   BOOTSTRAP_DIR (optional) - directory for transient bootstrap clones
#                              (the bare git-sdk fetch and build-extra
#                              checkout used to drive please.sh).
#                              Falls back to TEMP, then TMP, then errors
#                              if none are set.
#
# Arguments:
#   $1  sdk_repo        e.g. git-for-windows/git-sdk-64
#   $2  mingwprefix     e.g. mingw64 or clangarm64
#   $3  sdk_output_dir  Windows or MSYS path where the SDK will be installed
#
# See:
#   https://github.com/git-for-windows/git-sdk-64/blob/main/.github/workflows/ci-artifacts.yml
#   https://github.com/git-for-windows/build-extra/blob/main/please.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/utils.sh"

if test $# -ne 3
then
	echo "Usage: $0 <sdk_repo> <mingwprefix> <sdk_output_dir>" >&2
	exit 1
fi

sdk_repo="$1"
mingwprefix="$2"
sdk_output="$3"

bootstrap_dir="${BOOTSTRAP_DIR:-${TEMP:-${TMP:-}}}"
if test -z "$bootstrap_dir"
then
	echo "BOOTSTRAP_DIR (or TEMP/TMP) must be set" >&2
	exit 1
fi

bootstrap="$(to_unix_path "$bootstrap_dir")"
sdk="$(to_unix_path "$sdk_output")"

sdk_bare="$bootstrap/sdk-bare.git"
bootstrap_be="$bootstrap/build-extra-bootstrap"

git init --bare "$sdk_bare"
git --git-dir="$sdk_bare" remote add origin "https://github.com/$sdk_repo"
git --git-dir="$sdk_bare" config remote.origin.promisor true
git --git-dir="$sdk_bare" config remote.origin.partialCloneFilter blob:none
git --git-dir="$sdk_bare" fetch --depth=1 origin HEAD
git --git-dir="$sdk_bare" update-ref --no-deref HEAD FETCH_HEAD

# please.sh is the bootstrap; build-extra gets cloned again into the SDK
# in a separate task so `please.sh build-mingw-w64-git` can find it at
# /usr/src/build-extra under the SDK's bash.
git clone --depth=1 --single-branch -b main \
	https://github.com/git-for-windows/build-extra \
	"$bootstrap_be"

# Architecture is auto-detected from the bare clone's HEAD tree
# (clangarm64/ vs usr/x86_64-pc-msys/).
bash "$bootstrap_be/please.sh" create-sdk-artifact \
	--sdk="$sdk_bare" --out="$sdk" build-installers

# Expose the SDK's bash and the matching MinGW toolchain to subsequent
# tasks.
echo "##vso[task.prependpath]$(to_windows_path "$sdk/usr/bin")"
echo "##vso[task.prependpath]$(to_windows_path "$sdk/$mingwprefix/bin")"
