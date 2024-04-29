#!/bin/sh

test_description='test git repo structure'

. ./test-lib.sh

object_type_disk_usage() {
	disk_usage_opt="--disk-usage"

	if test "$2" = "true"
	then
		disk_usage_opt="--disk-usage=human"
	fi

	if test "$1" = "all"
	then
		git rev-list --all --objects $disk_usage_opt
	else
		git rev-list --all --objects $disk_usage_opt \
			--filter=object:type=$1 --filter-provided-objects
	fi
}

check_structure_summary() {
	sed -n "1,$(wc -l <expect)p" "$1" >summary &&
	test_cmp expect summary
}

expected_size_histograms() {
	git rev-list --all --objects --no-object-names >oids &&
	git cat-file \
		--batch-check="%(objecttype) %(objectsize) %(objectsize:disk)" \
		<oids >sizes &&
	awk '
		$1 == "tag" { next }
		{
			bin = 0
			for (size = $2; size >= 16; size = int(size / 16))
				bin++
			key = "objects." $1 "s.histogram.size." bin
			count[key]++
			inflated[key] += $2
			disk[key] += $3
		}
		END {
			for (key in count) {
				printf "%s.count=%.0f\n", key, count[key]
				printf "%s.inflated_size=%.0f\n",
					key, inflated[key]
				printf "%s.disk_size=%.0f\n", key, disk[key]
			}
		}
	' sizes
}

test_expect_success 'empty repository' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		cat >expect <<-\EOF &&
		| Repository structure      | Value  |
		| ------------------------- | ------ |
		| * References              |        |
		|   * Count                 |    0   |
		|     * Branches            |    0   |
		|     * Tags                |    0   |
		|       * Annotated         |    0   |
		|     * Remotes             |    0   |
		|     * Others              |    0   |
		|   * Symbolic refs         |    0   |
		|   * Loose refs            |    0   |
		|   * Packed refs           |    0   |
		|   * Refname length        |        |
		|     * Local               |        |
		|       * Maximum           |    0   |
		|       * Total             |    0   |
		|     * Remote              |        |
		|       * Maximum           |    0   |
		|       * Total             |    0   |
		|                           |        |
		| * Reachable objects       |        |
		|   * Count                 |    0   |
		|     * Commits             |    0   |
		|     * Trees               |    0   |
		|     * Blobs               |    0   |
		|     * Tags                |    0   |
		|   * Inflated size         |    0 B |
		|     * Commits             |    0 B |
		|     * Trees               |    0 B |
		|     * Blobs               |    0 B |
		|     * Tags                |    0 B |
		|   * Disk size             |    0 B |
		|     * Commits             |    0 B |
		|     * Trees               |    0 B |
		|     * Blobs               |    0 B |
		|     * Tags                |    0 B |
		|                           |        |
		| * Largest objects         |        |
		|   * Commits               |        |
		|     * Maximum size        |    0 B |
		|     * Maximum parents     |    0   |
		|   * Trees                 |        |
		|     * Maximum size        |    0 B |
		|     * Maximum entries     |    0   |
		|   * Blobs                 |        |
		|     * Maximum size        |    0 B |
		|   * Tags                  |        |
		|     * Maximum size        |    0 B |
		EOF

		git repo structure >out 2>err &&

		test_cmp expect out &&
		test_line_count = 0 err
	)
'

test_expect_success SHA1 'repository with references and objects' '
	test_when_finished "rm -rf repo" &&
	git init --initial-branch=main --ref-format=files repo &&
	(
		cd repo &&
		test_commit_bulk 1005 &&
		git tag -a foo -m bar &&

		oid="$(git rev-parse HEAD)" &&
		git update-ref refs/remotes/origin/foo "$oid" &&
		git symbolic-ref refs/remotes/origin/HEAD \
			refs/remotes/origin/foo &&

		# Also creates a commit, tree, and blob.
		git notes add -m foo &&

		# The tags disk size is handled specially due to the
		# git-rev-list(1) --disk-usage=human option printing the full
		# "byte/bytes" unit string instead of just "B".
		cat >expect <<-EOF &&
		| Repository structure      | Value      |
		| ------------------------- | ---------- |
		| * References              |            |
		|   * Count                 |      5     |
		|     * Branches            |      1     |
		|     * Tags                |      1     |
		|       * Annotated         |      1     |
		|     * Remotes             |      2     |
		|     * Others              |      1     |
		|   * Symbolic refs         |      1     |
		|   * Loose refs            |      5     |
		|   * Packed refs           |      0     |
		|   * Refname length        |            |
		|     * Local               |            |
		|       * Maximum           |     18     |
		|       * Total             |     46     |
		|     * Remote              |            |
		|       * Maximum           |     24     |
		|       * Total             |     47     |
		|                           |            |
		| * Reachable objects       |            |
		|   * Count                 |   3.02 k   |
		|     * Commits             |   1.01 k   |
		|     * Trees               |   1.01 k   |
		|     * Blobs               |   1.01 k   |
		|     * Tags                |      1     |
		|   * Inflated size         |  16.03 MiB |
		|     * Commits             | 217.92 KiB |
		|     * Trees               |  15.81 MiB |
		|     * Blobs               |  11.68 KiB |
		|     * Tags                |    132 B   |
		|   * Disk size             | $(object_type_disk_usage all true) |
		|     * Commits             | $(object_type_disk_usage commit true) |
		|     * Trees               | $(object_type_disk_usage tree true) |
		|     * Blobs               |  $(object_type_disk_usage blob true) |
		|     * Tags                |    $(object_type_disk_usage tag) B   |
		|                           |            |
		| * Largest objects         |            |
		|   * Commits               |            |
		|     * Maximum size    [1] |    223 B   |
		|     * Maximum parents [2] |      1     |
		|   * Trees                 |            |
		|     * Maximum size    [3] |  32.29 KiB |
		|     * Maximum entries [4] |   1.01 k   |
		|   * Blobs                 |            |
		|     * Maximum size    [5] |     13 B   |
		|   * Tags                  |            |
		|     * Maximum size    [6] |    132 B   |

		[1] 0dc91eb18580102a3a216c8bfecedeba2b9f9b9a
		[2] 0dc91eb18580102a3a216c8bfecedeba2b9f9b9a
		[3] 60665251ab71dbd8c18d9bf2174f4ee0d58aa06c
		[4] 60665251ab71dbd8c18d9bf2174f4ee0d58aa06c
		[5] 97d808e45116bf02103490294d3d46dad7a2ac62
		[6] 4dae4f5954f5e6feb3577cfb1b181daa3fd3afd2
		EOF

		git repo structure >out 2>err &&

		check_structure_summary out &&
		test_line_count = 0 err
	)
'

test_expect_success SHA1 'lines and nul format' '
	test_when_finished "rm -rf repo" &&
	git init --initial-branch=main --ref-format=files repo &&
	(
		cd repo &&
		test_commit_bulk 42 &&
		git tag lightweight-tag-is-not-counted-as-annotated &&
		git tag -a foo -m bar &&

		cat >expect <<-EOF &&
		references.branches.count=1
		references.tags.count=2
		references.tags.annotated.count=1
		references.remotes.count=0
		references.others.count=0
		references.symbolic.count=0
		references.loose.count=3
		references.packed.count=0
		references.local.max_length=53
		references.local.total_length=81
		references.remotes.max_length=0
		references.remotes.total_length=0
		objects.commits.count=42
		objects.trees.count=42
		objects.blobs.count=42
		objects.tags.count=1
		objects.commits.inflated_size=9225
		objects.trees.inflated_size=28554
		objects.blobs.inflated_size=453
		objects.tags.inflated_size=132
		objects.commits.disk_size=$(object_type_disk_usage commit)
		objects.trees.disk_size=$(object_type_disk_usage tree)
		objects.blobs.disk_size=$(object_type_disk_usage blob)
		objects.tags.disk_size=$(object_type_disk_usage tag)
		objects.commits.max_size=221
		objects.commits.max_size_oid=de3508174b5c2ace6993da67cae9be9069e2df39
		objects.trees.max_size=1335
		objects.trees.max_size_oid=09931deea9d81ec21300d3e13c74412f32eacec5
		objects.blobs.max_size=11
		objects.blobs.max_size_oid=eaeeedced46482bd4281fda5a5f05ce24854151f
		objects.tags.max_size=132
		objects.tags.max_size_oid=1ee0f2b16ea37d895dbe9dbd76cd2ac70446176c
		objects.commits.max_parents=1
		objects.commits.max_parents_oid=de3508174b5c2ace6993da67cae9be9069e2df39
		objects.trees.max_entries=42
		objects.trees.max_entries_oid=09931deea9d81ec21300d3e13c74412f32eacec5
		EOF

		git repo structure --format=lines >out 2>err &&

		check_structure_summary out &&
		test_line_count = 0 err &&

		git repo structure --format=nul >out 2>err &&
		tr "\012\000" "=\012" <out >actual &&

		check_structure_summary actual &&
		test_line_count = 0 err &&

		# "-z", as a synonym to "--format=nul", participates in the
		# usual "last one wins" rule.
		git repo structure --format=table -z >out 2>err &&
		tr "\012\000" "=\012" <out >actual &&

		check_structure_summary actual &&
		test_line_count = 0 err
	)
'

test_expect_success 'progress meter option' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		test_commit foo &&

		GIT_PROGRESS_DELAY=0 git repo structure --progress >out 2>err &&

		test_file_not_empty out &&
		test_grep "Counting references: 2, done." err &&
		test_grep "Counting objects: 3, done." err &&

		GIT_PROGRESS_DELAY=0 git repo structure --no-progress >out 2>err &&

		test_file_not_empty out &&
		test_line_count = 0 err
	)
'

test_expect_success 'object histograms cover size and entry boundaries' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		for size in 0 1 15 16 255 256 4095 4096
		do
			test-tool genzeros "$size" >blob-$size &&
			git add blob-$size || return 1
		done &&
		tree=$(git write-tree) &&
		commit=$(git commit-tree "$tree" -m blobs) &&
		git update-ref refs/heads/blobs "$commit" &&
		empty_blob=$(git hash-object -w --stdin </dev/null) &&
		for entries in 0 3 4 15 16 63 64
		do
			i=0 &&
			while test "$i" -lt "$entries"
			do
				printf "100644 blob %s\tfile-%s\n" \
					"$empty_blob" "$i" &&
				i=$((i + 1)) || return 1
			done >tree-input &&
			tree=$(git mktree <tree-input) &&
			commit=$(git commit-tree "$tree" -m "tree $entries") &&
			git update-ref refs/heads/tree-$entries "$commit" ||
			return 1
		done &&

		for storage in loose packed
		do
			if test "$storage" = packed
			then
				git repack -ad
			fi &&
			expected_size_histograms >expect-unsorted &&
			sort expect-unsorted >expect-sizes &&
			git repo structure --format=lines >out &&
			sed -n "/^objects\..*\.histogram\.size\./p" \
				out >actual-unsorted &&
			sort actual-unsorted >actual-sizes &&
			test_cmp expect-sizes actual-sizes &&

			cat >expect <<-\EOF &&
			objects.blobs.histogram.size.0.count=3
			objects.blobs.histogram.size.1.count=2
			objects.blobs.histogram.size.2.count=2
			objects.blobs.histogram.size.3.count=1
			EOF
			sed -n "/^objects\.blobs\.histogram\..*\.count=/p" \
				out >actual &&
			test_cmp expect actual &&

			key=objects.trees.histogram.entries &&
			cat >expect <<-EOF &&
			$key.0.count=2
			$key.1.count=3
			$key.2.count=2
			$key.3.count=1
			EOF
			sed -n "/^$key\..*\.count=/p" out >actual &&
			test_cmp expect actual &&

			git repo structure --format=nul >nul &&
			tr "\012\000" "=\012" <nul >decoded &&
			test_cmp out decoded &&

			git repo structure >table &&
			for kind in "Commit parent" "Commit size" \
				"Tree entry" "Tree size" "Blob size"
			do
				test_grep "| $kind histogram " table ||
				return 1
			done &&
			sed -n "/^| Blob size histogram /,\$p" table >blobs &&
			for range in 0..15 16..255 256..4095 4096..65535
			do
				test_grep -F "| * $range " blobs || return 1
			done &&

			tree=$(git rev-parse refs/heads/tree-16^{tree}) &&
			format="%(objectsize) %(objectsize:disk)" &&
			echo "$tree" |
				git cat-file --batch-check="$format" \
				>tree-size &&
			read inflated disk <tree-size &&
			cat >expect <<-EOF &&
			$key.2.count=1
			$key.2.inflated_size=$inflated
			$key.2.disk_size=$disk
			EOF
			git repo structure --format=lines \
				--ref-filter=refs/heads/tree-16 >filtered &&
			sed -n "/^objects\.trees\.histogram\.entries\./p" \
				filtered >actual &&
			test_cmp expect actual || return 1
		done &&

		git repo structure --format=lines \
			--ref-filter=refs/heads/missing >out &&
		test_grep ! "\.histogram\." out
	)
'

test_expect_success 'commit parent histogram groups 31 or more parents' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		tree=$(git mktree </dev/null) &&
		set -- &&
		for i in $(test_seq 1 32)
		do
			parent=$(git commit-tree "$tree" -m "parent $i") &&
			set -- "$@" -p "$parent" &&
			if test "$i" = 1
			then
				root=$parent
			fi &&
			if test "$i" = 31
			then
				commit=$(git commit-tree "$tree" \
					"$@" -m boundary) &&
				git update-ref refs/heads/boundary "$commit"
			fi || return 1
		done &&
		commit=$(git commit-tree "$tree" "$@" -m overflow) &&
		git update-ref refs/heads/overflow "$commit" &&
		one=$(git commit-tree "$tree" -p "$root" -m one) &&
		git update-ref refs/heads/one "$one" &&
		two=$(git commit-tree "$tree" -p "$root" -p "$one" -m two) &&
		git update-ref refs/heads/two "$two" &&

		cat >expect <<-\EOF &&
		objects.commits.histogram.parents.0.count=32
		objects.commits.histogram.parents.1.count=1
		objects.commits.histogram.parents.2.count=1
		objects.commits.histogram.parents.31.count=2
		EOF
		git repo structure --format=lines >out &&
		sed -n "/^objects\.commits\.histogram\.parents\./p" \
			out >actual &&
		test_cmp expect actual &&
		test_grep "^objects.commits.max_parents=32$" out &&
		git repo structure >table &&
		test_grep "^| 31+ *| *2 *|$" table
	)
'

for ref_format in files reftable
do
	test_expect_success "$ref_format reference statistics" '
		test_when_finished "rm -rf repo" &&
		git init --initial-branch=main \
			--ref-format="$ref_format" repo &&
		(
			cd repo &&
			test_commit --no-tag one &&
			git tag v1 &&
			git update-ref refs/notes/commits HEAD &&
			git update-ref refs/remotes/origin/long-branch HEAD &&
			git symbolic-ref refs/heads/alias refs/heads/main &&
			git symbolic-ref refs/remotes/origin/HEAD \
				refs/remotes/origin/long-branch &&
			git pack-refs --all &&
			test_commit --no-tag two &&

			if test "$ref_format" = files
			then
				loose=3 &&
				packed=3
			else
				loose=0 &&
				packed=0
			fi &&
			cat >expect <<-EOF &&
			references.branches.count=2
			references.tags.count=1
			references.tags.annotated.count=0
			references.remotes.count=2
			references.others.count=1
			references.symbolic.count=2
			references.loose.count=$loose
			references.packed.count=$packed
			references.local.max_length=18
			references.local.total_length=61
			references.remotes.max_length=31
			references.remotes.total_length=55
			EOF
			git repo structure --format=lines >out &&
			sed -n "/^references\./p" out >actual &&
			test_cmp expect actual &&

			if test "$ref_format" = files
			then
				loose=1 &&
				packed=1
			fi &&
			cat >expect <<-EOF &&
			references.branches.count=0
			references.tags.count=0
			references.tags.annotated.count=0
			references.remotes.count=2
			references.others.count=0
			references.symbolic.count=1
			references.loose.count=$loose
			references.packed.count=$packed
			references.local.max_length=0
			references.local.total_length=0
			references.remotes.max_length=31
			references.remotes.total_length=55
			EOF
			git repo structure --format=nul \
				--ref-filter="refs/remotes/origin/*" >out &&
			tr "\012\000" "=\012" <out >decoded &&
			sed -n "/^references\./p" decoded >actual &&
			test_cmp expect actual &&

			sed "s/=[0-9]*$/=0/" expect >expect-empty &&
			git repo structure --format=lines \
				--ref-filter="refs/does-not-exist/" >out &&
			sed -n "/^references\./p" out >actual &&
			test_cmp expect-empty actual
		)
	'
done

test_expect_success '--ref-filter narrows the set of refs' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		test_commit foo &&
		git tag v1 &&
		git update-ref refs/remotes/origin/main HEAD &&

		git repo structure --format=lines \
			--ref-filter="refs/heads/*" >out &&
		test_grep "^references.branches.count=1$" out &&
		test_grep "^references.tags.count=0$" out &&
		test_grep "^references.remotes.count=0$" out
	)
'

test_expect_success '--ref-filter unions multiple patterns' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		test_commit foo &&
		git tag v1 &&
		git update-ref refs/remotes/origin/main HEAD &&

		git repo structure --format=lines \
			--ref-filter="refs/heads/*" \
			--ref-filter="refs/tags/*" >out &&
		test_grep "^references.branches.count=1$" out &&
		test_grep "^references.tags.count=2$" out &&
		test_grep "^references.remotes.count=0$" out
	)
'

test_expect_success '--top omitted: no top.* keys' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		test_commit foo &&

		git repo structure --format=lines >out &&
		test_grep ! "\.top\." out
	)
'

test_expect_success '--top=N reports the N largest paths per axis' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		mkdir -p dir1 dir2 &&
		echo small >dir1/small.txt &&
		printf "%010000d" 0 >dir2/big.txt &&
		git add . &&
		test_tick &&
		git commit -m commit &&

		git repo structure --format=lines --top=2 >out &&

		# Two ranked entries on each axis for both types.
		for axis in by_count by_disk_size by_inflated_size
		do
			for type in trees blobs
			do
				key=objects.${type}.top.${axis} &&
				test_grep -E "^${key}\.1\.path=" out &&
				test_grep -E "^${key}\.2\.path=" out &&
				test_grep ! -E "^${key}\.3\." out || return 1
			done
		done &&

		# The big blob outranks the small one on disk and inflated.
		key=objects.blobs.top &&
		test_grep "^${key}.by_disk_size.1.path=dir2/big.txt$" out &&
		test_grep "^${key}.by_inflated_size.1.path=dir2/big.txt$" out
	)
'

test_expect_success '--top rejects negative values' '
	test_must_fail git repo structure --top=-1 2>err &&
	test_grep "must be non-negative" err
'

test_expect_success 'repo.structure.top supplies the default for --top' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		test_commit foo &&

		git -c repo.structure.top=2 \
			repo structure --format=lines >with-config &&
		test_grep "^objects.blobs.top.by_count.1.path=" with-config &&

		git -c repo.structure.top=2 \
			repo structure --format=lines --top=0 >cli-override &&
		test_grep ! "\.top\." cli-override
	)
'

test_expect_success 'git repo structure -h shows only repo structure usage' '
	git repo structure -h >actual &&
	test_grep "git repo structure" actual &&
	test_grep ! "git repo info" actual
'

test_done
