#!/bin/sh
#
# Promote a microsoft/git release into the microsoft/VFSForGit repo.
#
# Usage:
#   .github/release-vfsforgit.sh [<TAG_NAME>]
#
# If TAG_NAME is omitted, the latest microsoft/git release is used.
#
# Prerequisites:
#   - `gh` authenticated (via `gh auth login`) as a user with push
#     access to microsoft/VFSForGit.
#   - `git` and `sed` on PATH.
#
# Given a release tag on microsoft/git (e.g. v2.54.0.vfs.0.4), this
# script opens a pull request against microsoft/VFSForGit that bumps
# the `GIT_VERSION` default in `.github/workflows/build.yaml` so that
# VFSForGit builds pick up the newly promoted release by default.

set -eu

die () {
	echo "error: $*" >&2
	exit 1
}

TAG_NAME=${1-}
if [ -z "$TAG_NAME" ]; then
	echo "==> No tag given; resolving latest microsoft/git release"
	TAG_NAME=$(gh release view -R microsoft/git \
		--json tagName --jq .tagName)
	test -n "$TAG_NAME" || die "could not determine latest release tag"
fi

echo "==> Tag:       $TAG_NAME"

REPO=microsoft/VFSForGit
BRANCH="automation/gitrelease-$TAG_NAME"
FILE=.github/workflows/build.yaml
RELEASE_URL="https://github.com/microsoft/git/releases/tag/$TAG_NAME"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

echo "==> Sparse-cloning $REPO"
gh repo clone "$REPO" "$workdir/vfsforgit" -- \
	--filter=blob:none --no-checkout --depth=1 --quiet
cd "$workdir/vfsforgit"
git sparse-checkout set "$FILE"
git checkout -b "$BRANCH" --quiet

echo "==> Bumping GIT_VERSION in $FILE"
sed "/GIT_VERSION/s/|| '[^']*' }}/|| '$TAG_NAME' }}/" \
	<"$FILE" >"$FILE.new" &&
mv -f "$FILE.new" "$FILE"

git --no-pager diff -- "$FILE"

git commit -m "Update default Microsoft Git version to $TAG_NAME" \
	-- "$FILE"

git push origin "$BRANCH"

pr_body="Update the default Microsoft Git version used by VFS for Git
to the newly promoted [\`$TAG_NAME\`]($RELEASE_URL) release."

pr_url=$(gh pr create \
	--repo "$REPO" \
	--head "$BRANCH" \
	--title "Update default Microsoft Git version to $TAG_NAME" \
	--body "$pr_body")

echo "==> Created:   $pr_url"
