#!/bin/bash
#
# Sign Windows files using the ESRP client (Authenticode).
# Usage: esrpsign.sh <file1> [file2 ...]
#
# Required environment variables:
#   ESRP_TOOL             - Path to ESRPClient.exe
#   ESRP_CLIENT_ID        - Entra App ID for ESRP authentication
#   ESRP_TENANT_ID        - Entra Tenant ID
#   ESRP_AUTH_CERT_NAME   - Subject name of the authentication certificate
#   ESRP_SIGN_CERT_NAME   - Subject name of the request signing certificate
#
# The script generates the auth and input JSON files and sets the
# following ESRP client environment variables automatically:
#   ESRP_AUTH_CONFIG       - Path to the generated auth JSON
#   ESRP_POLICY_CONFIG     - Path to the generated policy JSON
#   ESRP_SESSION_CONFIG    - Not set; ESRP client defaults are used
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
if [ -z "${ESRP_CLIENT_ID:-}" ]; then
	echo "error: ESRP_CLIENT_ID environment variable must be set" >&2
	exit 1
fi
if [ -z "${ESRP_TENANT_ID:-}" ]; then
	echo "error: ESRP_TENANT_ID environment variable must be set" >&2
	exit 1
fi
if [ -z "${ESRP_AUTH_CERT_NAME:-}" ]; then
	echo "error: ESRP_AUTH_CERT_NAME environment variable must be set" >&2
	exit 1
fi
if [ -z "${ESRP_SIGN_CERT_NAME:-}" ]; then
	echo "error: ESRP_SIGN_CERT_NAME environment variable must be set" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"

echo "==> ESRP signing tool: $ESRP_TOOL"
echo "==> Working directory: $WORK_DIR"

if [ ! -f "$ESRP_TOOL" ]; then
	echo "error: ESRPClient.exe not found at $ESRP_TOOL" >&2
	exit 1
fi

# Convert a path to Windows format (for ESRPClient.exe)
to_windows_path () {
	cygpath -w "$1" 2>/dev/null || echo "$1"
}

# Generate auth JSON and set ESRP_AUTH_CONFIG
echo "==> Generating auth JSON..."
auth_json="$WORK_DIR/auth.json"
jq -n \
	--arg tenant "$ESRP_TENANT_ID" \
	--arg client "$ESRP_CLIENT_ID" \
	--arg authCert "$ESRP_AUTH_CERT_NAME" \
	--arg signCert "$ESRP_SIGN_CERT_NAME" \
	'{
		Version: "1.0.0",
		AuthenticationType: "AAD_CERT",
		TenantId: $tenant,
		ClientId: $client,
		AuthCert: {
			SubjectName: $authCert,
			StoreLocation: "LocalMachine",
			StoreName: "My"
		},
		RequestSigningCert: {
			SubjectName: $signCert,
			StoreLocation: "LocalMachine",
			StoreName: "My"
		}
	}' > "$auth_json"

# Build the SignRequestFiles JSON array
echo "==> Preparing files for signing ($# file(s))..."
files_json="[]"
for file in "$@"; do
	if [ ! -f "$file" ]; then
		echo "error: file not found: $file" >&2
		exit 1
	fi

	abs_path="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
	win_path="$(to_windows_path "$abs_path")"
	echo "    - $win_path"
	files_json="$(echo "$files_json" | jq \
		--arg path "$win_path" \
		'. + [{SourceLocation: $path, DestinationLocation: $path}]')"
done

# Generate the input JSON
input_json="$WORK_DIR/input.json"
output_json="$WORK_DIR/output.json"

echo "==> Generating input JSON: $input_json"
jq -n \
	--argjson files "$files_json" \
	'{
		Version: "1.0.0",
		SignBatches: [{
			SourceLocationType: "UNC",
			DestinationLocationType: "UNC",
			SignRequestFiles: $files,
			SigningInfo: {
				Operations: [
					{
						KeyCode: "CP-231522",
						OperationCode: "SigntoolSign",
						ToolName: "sign",
						ToolVersion: "1.0",
						Parameters: {
							OpusName: "Microsoft",
							OpusInfo: "https://www.microsoft.com",
							FileDigest: "/fd SHA256",
							PageHash: "/NPH",
							TimeStamp: "/tr \"http://rfc3161.gtm.corp.microsoft.com/TSS/HttpTspServer\" /td sha256"
						}
					},
					{
						KeyCode: "CP-231522",
						OperationCode: "SigntoolVerify",
						ToolName: "sign",
						ToolVersion: "1.0",
						Parameters: {}
					}
				]
			}
		}]
	}' > "$input_json"

# Generate policy JSON and set ESRP_POLICY_CONFIG
echo "==> Generating policy JSON..."
policy_json="$WORK_DIR/policy.json"
jq -n \
	'{
		Version: "1.0.0",
		Intent: "ProductRelease",
		ContentType: "Binaries",
		ContentOrigin: "1stParty",
		ProductState: "Current",
		Audience: "ExternalBroad"
	}' > "$policy_json"

# Export environment variables for ESRP client
export ESRP_AUTH_CONFIG="$(to_windows_path "$auth_json")"
export ESRP_POLICY_CONFIG="$(to_windows_path "$policy_json")"

# Sign the files
echo "==> Invoking ESRP client..."
"$(to_windows_path "$ESRP_TOOL")" sign \
	-i "$(to_windows_path "$input_json")" \
	-o "$(to_windows_path "$output_json")"

echo "==> Signing complete. Output: $output_json"
