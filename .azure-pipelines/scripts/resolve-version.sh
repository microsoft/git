#!/bin/bash
#
# Resolve version and tag information from the current HEAD commit.
# Validates that HEAD is an annotated version tag matching GIT-VERSION-GEN.
#
# Sets the following ADO output variables (via ##vso):
#   git_version  - Version string without "v" prefix (e.g., 2.53.0.vfs.0.0)
#   tag_name     - Full tag name (e.g., v2.53.0.vfs.0.0)
#   tag_sha      - Commit SHA of HEAD
#
# Also updates the build number to include the tag name.
#
set -euo pipefail

echo "HEAD: $(git rev-parse HEAD)"

# Determine the tag pointing at HEAD
tag_name=$(git describe --exact-match --match "v[0-9]*vfs*" HEAD 2>/dev/null) || {
	echo "##vso[task.logissue type=error]HEAD is not tagged with a version tag"
	exit 1
}

# Verify the tag is annotated (not lightweight)
tag_type=$(git cat-file -t "refs/tags/$tag_name")
if [ "$tag_type" != "tag" ]; then
	echo "##vso[task.logissue type=error]Tag $tag_name is not annotated (type: $tag_type)"
	exit 1
fi

tag_sha=$(git rev-parse HEAD)
git_version="${tag_name#v}"

# Verify the version matches GIT-VERSION-GEN
make GIT-VERSION-FILE
expected_version="${git_version//-rc/.rc}"
actual_version=$(sed -n 's/^GIT_VERSION *= *//p' < GIT-VERSION-FILE)
if [ "$expected_version" != "$actual_version" ]; then
	echo "##vso[task.logissue type=error]GIT-VERSION-FILE ($actual_version) does not match tag $tag_name ($expected_version)"
	exit 1
fi

echo "Git version: $git_version"
echo "Tag name: $tag_name"
echo "Tag SHA: $tag_sha"
echo "##vso[task.setvariable variable=git_version;isOutput=true;isReadOnly=true]$git_version"
echo "##vso[task.setvariable variable=tag_name;isOutput=true;isReadOnly=true]$tag_name"
echo "##vso[task.setvariable variable=tag_sha;isOutput=true;isReadOnly=true]$tag_sha"
echo "##vso[build.updatebuildnumber]${tag_name} (${BUILD_BUILDNUMBER:-unknown})"
