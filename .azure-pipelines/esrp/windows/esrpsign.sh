#!/bin/bash
#
# Sign Windows files using the ESRP client (Authenticode).
# Usage: esrpsign.sh <file1> [file2 ...]
#
# Required environment variables:
#   ESRP_TOOL             - Path to ESRPClient.exe
#   ESRP_AUTH             - Path to the ESRP auth JSON file
#   SYSTEM_ACCESSTOKEN    - ADO system access token (OAuth bearer)
#
# Optional environment variables:
#   ESRP_KEYCODE          - Signing key code (default: CP-231522)
#
# The script generates the auth and input JSON files and sets the
# following ESRP client environment variables automatically:
#   ESRP_AUTH_CONFIG      - Path to the auth JSON file
#   ESRP_POLICY_CONFIG    - Path to the policy JSON file
#   ESRP_SESSION_CONFIG   - Not set; ESRP client defaults are used
#
set -euo pipefail

if [ $# -lt 1 ]; then
	echo "usage: esrpsign.sh <file> [file ...]" >&2
	exit 1
fi

if [ -z "${ESRP_TOOL:-}" ]; then
	echo "error: ESRP_TOOL environment variable must be set" >&2
	exit 1
fi
if [ -z "${ESRP_AUTH:-}" ]; then
	echo "error: ESRP_AUTH environment variable must be set" >&2
	exit 1
fi
if [ -z "${SYSTEM_ACCESSTOKEN:-}" ]; then
	echo "error: SYSTEM_ACCESSTOKEN environment variable must be set" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../../scripts/windows/utils.sh"

# Check for overriden key code, otherwise use default (Microsoft Third-Party/OSS)
ESRP_KEYCODE="${ESRP_KEYCODE:-CP-231522}"

# Create work dir and resolve its Windows path by cd-ing into it.
WORK_DIR="$(mktemp -d)"
WORK_DIR_WIN="$(cd "$WORK_DIR" && pwd -W | sed 's|/|\\|g')"

echo "==> ESRP signing tool: $ESRP_TOOL"
echo "==> Working directory: $WORK_DIR"

if [ ! -f "$ESRP_TOOL" ]; then
	echo "error: ESRPClient.exe not found at $ESRP_TOOL" >&2
	exit 1
fi

# Build the SignRequestFiles JSON array
echo "==> Preparing files for signing ($# file(s))..."
files_json=""
for file in "$@"; do
	if [ ! -f "$file" ]; then
		echo "error: file not found: $file" >&2
		exit 1
	fi

	abs_path="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
	win_path="$(to_windows_path "$abs_path")"
	# Escape backslashes for JSON
	win_path_escaped="${win_path//\\/\\\\}"
	echo "    - $win_path"

	if [ -n "$files_json" ]; then
		files_json+=","
	fi
	files_json+="
	{
		\"SourceLocation\": \"$win_path_escaped\",
		\"DestinationLocation\": \"$win_path_escaped\"
	}"
done

# Generate the input JSON
input_json="$WORK_DIR/input.json"
output_json="$WORK_DIR/output.json"

echo "==> Generating input JSON: $input_json"
cat > "$input_json" <<-EOF
	{
		"Version": "1.0.0",
		"SignBatches": [
			{
				"SourceLocationType": "UNC",
				"DestinationLocationType": "UNC",
				"SignRequestFiles": [$files_json
				],
				"SigningInfo": {
					"Operations": [
						{
							"KeyCode": "$ESRP_KEYCODE",
							"OperationCode": "SigntoolSign",
							"ToolName": "sign",
							"ToolVersion": "1.0",
							"Parameters": {
								"OpusName": "Microsoft",
								"OpusInfo": "https://www.microsoft.com",
								"FileDigest": "/fd SHA256",
								"PageHash": "/NPH",
								"TimeStamp": "/tr \"http://rfc3161.gtm.corp.microsoft.com/TSS/HttpTspServer\" /td sha256"
							}
						},
						{
							"KeyCode": "$ESRP_KEYCODE",
							"OperationCode": "SigntoolVerify",
							"ToolName": "sign",
							"ToolVersion": "1.0",
							"Parameters": {}
						}
					]
				}
			}
		]
	}
EOF

# Generate policy JSON
echo "==> Generating policy JSON..."
policy_json="$WORK_DIR/policy.json"
cat > "$policy_json" <<-EOF
	{
		"Version": "1.0.0",
		"Intent": "ProductRelease",
		"ContentType": "Binaries",
		"ContentOrigin": "1stParty",
		"ProductState": "Current",
		"Audience": "ExternalBroad"
	}
EOF

# Use auth JSON from ESRP_AUTH
export ESRP_AUTH_CONFIG="$(to_windows_path "$ESRP_AUTH")"
export ESRP_POLICY_CONFIG="$WORK_DIR_WIN\\policy.json"

# The ADO system access token is referenced in the auth JSON via the environment
# variable - export this so the ESRP client can pick it up when it runs.
export SYSTEM_ACCESSTOKEN

# Print generated JSON files for debugging
echo "==> Auth JSON:"
cat "$ESRP_AUTH"
echo ""
echo "==> Policy JSON:"
cat "$policy_json"
echo ""
echo "==> Input JSON:"
cat "$input_json"
echo ""

# Sign the files
esrp_tool_win="$(to_windows_path "$ESRP_TOOL")"
input_json_win="$WORK_DIR_WIN\\input.json"
output_json_win="$WORK_DIR_WIN\\output.json"

echo "==> ESRP_AUTH_CONFIG=$ESRP_AUTH_CONFIG"
echo "==> ESRP_POLICY_CONFIG=$ESRP_POLICY_CONFIG"
echo "==> Running: $esrp_tool_win sign -i $input_json_win -o $output_json_win"
"$esrp_tool_win" sign \
	-i "$input_json_win" \
	-o "$output_json_win"

echo "==> Signing complete."
echo "==> Output JSON:"
cat "$output_json"
