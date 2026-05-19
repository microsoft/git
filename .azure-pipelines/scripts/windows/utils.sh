#!/usr/bin/env bash
# Utilities for bash scripts running on Windows.
#
# Source this file from another bash script:
#     SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#     . "$SCRIPT_DIR/utils.sh"
#
# Functions:
#   to_windows_path <path>  - output a Windows-form (D:\foo) path.
#   to_unix_path    <path>  - output an MSYS-form (/d/foo) path.

# Convert a path to Windows form for tools that demand backslashes
# (e.g. ESRPClient.exe, ##vso[task.prependpath]).
# Useful when a script may run before the full Git for Windows SDK
# (which provides cygpath) is available. Falls back to pure-shell
# parsing when cygpath is not on PATH.
to_windows_path () {
	local drive rest root
	if command -v cygpath >/dev/null 2>&1; then
		cygpath -w "$1"
		return
	fi
	case "$1" in
	/[A-Za-z]/*)
		# /d/path -> D:\path
		drive=$(echo "$1" | cut -c2 | tr 'a-z' 'A-Z')
		rest=$(echo "$1" | cut -c3-)
		echo "${drive}:${rest}" | sed 's|/|\\|g'
		;;
	/*)
		# Absolute path under MSYS root
		root=$(cd / && pwd -W)
		echo "${root}${1}" | sed 's|/|\\|g'
		;;
	*)
		# Relative or already-Windows: just flip slashes
		echo "$1" | sed 's|/|\\|g'
		;;
	esac
}

# Convert a path to MSYS form for bash-friendly handling. Inverse of
# to_windows_path.
# Useful when a script may run before the full Git for Windows SDK
# (which provides cygpath) is available. Falls back to pure-shell
# parsing when cygpath is not on PATH.
to_unix_path () {
	local p drive rest
	if command -v cygpath >/dev/null 2>&1; then
		cygpath -u "$1"
		return
	fi
	# Normalize separators to forward slashes first.
	p="${1//\\//}"
	case "$p" in
	[A-Za-z]:/*)
		# D:/path -> /d/path
		drive=$(echo "$p" | cut -c1 | tr 'A-Z' 'a-z')
		rest=$(echo "$p" | cut -c3-)
		echo "/${drive}${rest}"
		;;
	*)
		echo "$p"
		;;
	esac
}
