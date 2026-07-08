#!/bin/sh
#
# Promote a microsoft/git release into the microsoft/homebrew-git tap.
#
# Usage:
#   .github/release-homebrew.sh [<TAG_NAME>]
#
# If TAG_NAME is omitted, the latest microsoft/git release is used.
#
# Prerequisites:
#   - `gh` authenticated (via `gh auth login`) as a user with push
#     access to microsoft/homebrew-git.
#   - `git`, `jq`, and `sed` on PATH.
#
# Given a release tag on microsoft/git (e.g. v2.54.0.vfs.0.4), this
# script looks up the macOS installer asset for that tag, extracts the
# SHA-256 digest reported by the GitHub Releases API (deliberately not
# re-hashed locally; see microsoft/homebrew-git#102), edits the
# `microsoft-git` cask in place preserving its indentation and quote
# style, pushes the update to the tap under a datetime-keyed branch,
# and opens a PR.
#
# This mirrors the behaviour of mjcheetham/update-homebrew@v1.5.1
# invoked with `type: cask`, `alwaysUsePullRequest: true`.

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

version=${TAG_NAME#v}
echo "==> Version:   $version"

# Refuse to downgrade the cask and short-circuit no-op runs. Look up
# the version currently in the tap and compare before fetching the
# release JSON or cloning.
current_content=$(gh api \
	repos/microsoft/homebrew-git/contents/Casks/microsoft-git.rb \
	-H "Accept: application/vnd.github.raw")
current_version=$(printf '%s\n' "$current_content" | sed -nE \
	"s/^[[:space:]]*version *['\"]([^'\"]*)['\"].*/\\1/p")
test -n "$current_version" || die "could not parse current cask version"
echo "==> Current:   $current_version"

if [ "$version" = "$current_version" ]; then
	echo "warning: cask is already at $version; nothing to do." >&2
	exit 0
fi
lowest=$(printf '%s\n%s\n' "$version" "$current_version" |
	sort -V | sed 1q)
if [ "$lowest" = "$version" ]; then
	die "regression: cask is at $current_version," \
		"refusing to downgrade to $version"
fi

echo "==> Fetching release metadata"
release_json=$(gh api \
	-H "Accept: application/vnd.github+json" \
	-H "X-GitHub-Api-Version: 2022-11-28" \
	"repos/microsoft/git/releases/tags/$TAG_NAME")

asset_pattern='git-(.*)\.pkg'
asset_json=$(jq -n \
	--argjson release "$release_json" \
	--arg pat "$asset_pattern" '
	[ $release.assets[] | select(.name | test($pat)) ] as $matches
	| if ($matches | length) == 0 then
		error("no asset matches pattern \($pat)")
	  elif ($matches | length) > 1 then
		error("multiple assets match pattern \($pat): " +
		      ([$matches[].name] | join(", ")))
	  else $matches[0] end')

digest=$(jq -n -r --argjson a "$asset_json" '$a.digest // ""')
case "$digest" in
sha256:*) sha256=${digest#sha256:} ;;
"")	die "asset has no 'digest' field" ;;
*)	die "asset digest is not sha256: $digest" ;;
esac

# Enforce 64 lowercase hex chars without spawning grep.
case "$sha256" in
*[!0-9a-f]* | "")
	die "asset digest is not lowercase hex: $sha256" ;;
esac
test ${#sha256} -eq 64 ||
	die "asset digest is not 64 chars long: $sha256"

echo "==> Asset:     $(jq -n -r --argjson a "$asset_json" '$a.name')"
echo "==> SHA-256:   $sha256"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

echo "==> Cloning microsoft/homebrew-git"
REPO=microsoft/homebrew-git
gh repo clone "$REPO" "$workdir/homebrew-git" -- \
	--depth=1 --quiet

cd "$workdir/homebrew-git"

# Preserve existing indentation and quote style, replacing only the
# value; matches mjcheetham/update-homebrew's setField regex. The
# `<file >file.new && mv -f file.new file` idiom sidesteps the
# incompatible `sed -i` spellings between GNU and BSD sed.
f=Casks/microsoft-git.rb
# Capture opening quote as \2, match value up to the matching quote.
q='(['\''"])[^'\''"]+\2'
sed -E \
	-e "s/^([[:space:]]*)version +$q/\\1version \\2$version\\2/" \
	-e "s/^([[:space:]]*)sha256 +$q/\\1sha256 \\2$sha256\\2/" \
	<"$f" >"$f.new" &&
mv -f "$f.new" "$f"

if git diff --quiet -- Casks/microsoft-git.rb; then
	echo "==> No changes needed; cask is already at $version."
	exit 0
fi

git --no-pager diff -- Casks/microsoft-git.rb

BRANCH=update-$(date +%Y-%m-%d-%H-%M-%S)
git switch -c $BRANCH
TITLE="microsoft-git: update to $version"
git commit -m "$TITLE" \
	-- Casks/microsoft-git.rb

git push origin HEAD

echo "==> Pushed:    $(git log -1 --format='%h %s')"

pr_url=$(gh pr create \
	--repo "$REPO" \
	--head "$BRANCH" \
	--title "$TITLE")

echo "==> Created:   $pr_url"
