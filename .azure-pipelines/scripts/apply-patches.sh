#!/usr/bin/env bash
# Apply all numbered patches from a directory to a target tree.
#
# Patches are applied in lexicographic order, so name them with
# zero-padded numeric prefixes (e.g. 0000-foo.patch, 0001-bar.patch).
#
# Arguments:
#   $1  patches_dir  Directory containing *.patch files
#   $2  target_dir   Directory to apply patches in (need not be a
#                    git repository; git apply works on any tree)

set -euo pipefail

if test $# -ne 2
then
	echo "Usage: $0 <patches-dir> <target-dir>" >&2
	exit 1
fi

patches_dir="$1"
target_dir="$2"

if test ! -d "$patches_dir"
then
	echo "Patches directory not found: $patches_dir" >&2
	exit 1
fi

if test ! -d "$target_dir"
then
	echo "Target directory not found: $target_dir" >&2
	exit 1
fi

shopt -s nullglob
patches=("$patches_dir"/*.patch)
if test ${#patches[@]} -eq 0
then
	echo "No patches found in $patches_dir"
	exit 0
fi

cd "$target_dir"
for patch in "${patches[@]}"
do
	echo "Applying $(basename "$patch")..."
	# Use patch(1) rather than `git apply` because the latter is
	# strict about context whitespace; CRLF/LF mismatches between
	# patch context (as authored) and the working tree (which may
	# be CRLF on Windows checkouts) trip it up. patch is more
	# forgiving by default.
	#
	# This matches the convention used by msys2/MINGW-packages
	# PKGBUILDs and git-for-windows/build-extra's get-sources.sh.
	command patch -p1 -i "$patch"
done
