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
		test_grep "^| 31+ *| *2 *|$" table &&

		key=objects.commits.largest.by_parents &&
		boundary=$(git rev-parse refs/heads/boundary) &&
		cat >expect <<-EOF &&
		$key.1.parents=32
		$key.1.oid=$commit
		$key.1.commit_oid=$commit
		$key.1.name_rev=overflow
		$key.2.parents=31
		$key.2.oid=$boundary
		$key.2.commit_oid=$boundary
		$key.2.name_rev=boundary
		$key.3.parents=2
		$key.3.oid=$two
		$key.3.commit_oid=$two
		$key.3.name_rev=two
		EOF
		git repo structure --format=lines --commit-parents=3 >out &&
		sed -n "/^$key\./p" out >actual &&
		test_cmp expect actual &&

		for limit in 9 10 12
		do
			git repo structure --format=lines \
				--commit-parents=$limit >out &&
			sed -n "s/\.oid=/.commit_oid=/p" out >expect &&
			sed -n "/\.commit_oid=/p" out >actual &&
			test_line_count = $limit actual &&
			test_cmp expect actual &&
			sed -n "s/^.*\.commit_oid=//p" out >oids &&
			git name-rev --name-only --annotate-stdin \
				<oids >expect &&
			sed -n "s/^.*\.name_rev=//p" out >actual &&
			test_cmp expect actual &&
			git repo structure --commit-parents=$limit >table &&
			sed -n "/^| Largest commits by parent count /,/^$/p" \
				table >parents &&
			test_line_count = $((limit + 3)) parents &&
			awk "
				!NF { next }
				!width { width = length }
				length != width {
					print length, width
					exit 1
				}
			" parents || return 1
		done
	)
'

test_expect_success 'largest object lists have independent sorted limits' '
	test_when_finished "rm -rf repo" &&
	git init --initial-branch=main repo &&
	(
		cd repo &&
		empty_blob=$(git hash-object -w --stdin </dev/null) &&
		test-tool genzeros 16 >big &&
		big=$(git hash-object -w big) &&
		printf abcdefghijklmnop >tied &&
		tied=$(git hash-object -w tied) &&
		empty_tree=$(git mktree </dev/null) &&
		cat >tree-input <<-EOF &&
		100644 blob $empty_blob	a
		100644 blob $big	b
		100644 blob $tied	c
		EOF
		wide=$(git mktree <tree-input) &&
		long=$(printf "%0200d" 0) &&
		cat >tree-input <<-EOF &&
		100644 blob $empty_blob	$long-a
		100644 blob $big	$long-b
		EOF
		narrow=$(git mktree <tree-input) &&
		printf "%04096d\n" 0 >message &&
		root=$(git commit-tree "$empty_tree" -F message) &&
		other=$(git commit-tree "$narrow" -m other) &&
		child=$(git commit-tree "$wide" -p "$root" -m child) &&
		merge=$(git commit-tree "$wide" -p "$child" -p "$other" \
			-m merge) &&
		git update-ref refs/heads/main "$merge" &&
		git update-ref refs/heads/empty "$root" &&
		root_size=$(git cat-file -s "$root") &&
		narrow_size=$(git cat-file -s "$narrow") &&
		commit_parents=objects.commits.largest.by_parents &&
		commit_sizes=objects.commits.largest.by_size &&
		tree_entries=objects.trees.largest.by_entries &&
		tree_sizes=objects.trees.largest.by_size &&
		blob_sizes=objects.blobs.largest.by_size &&
		printf "%s %s\n" \
			"$big" b "$big" "$long-b" \
			"$tied" c \
			"$empty_blob" a "$empty_blob" "$long-a" \
			>allowed-paths &&

		set -- --commit-parents=2 --commit-sizes=1 \
			--tree-entries=4 --tree-sizes=1 --blob-sizes=4 &&
		for storage in loose packed
		do
			if test "$storage" = packed
			then
				git repack -ad
			fi &&
			git repo structure --format=lines "$@" >out &&
			cat >expect <<-EOF &&
			$commit_parents.1.parents=2
			$commit_parents.1.oid=$merge
			$commit_parents.1.commit_oid=$merge
			$commit_parents.1.name_rev=main
			$commit_parents.2.parents=1
			$commit_parents.2.oid=$child
			$commit_parents.2.commit_oid=$child
			$commit_parents.2.name_rev=main~1
			$commit_sizes.1.inflated_size=$root_size
			$commit_sizes.1.oid=$root
			$commit_sizes.1.commit_oid=$root
			$commit_sizes.1.name_rev=empty
			$tree_entries.1.entries=3
			$tree_entries.1.oid=$wide
			$tree_entries.1.path=
			$tree_entries.2.entries=2
			$tree_entries.2.oid=$narrow
			$tree_entries.2.path=
			$tree_entries.3.entries=0
			$tree_entries.3.oid=$empty_tree
			$tree_entries.3.path=
			$tree_sizes.1.inflated_size=$narrow_size
			$tree_sizes.1.oid=$narrow
			$tree_sizes.1.path=
			EOF
			sed -n "/^$blob_sizes\./d; /\.largest\./p" \
				out >actual &&
			test_cmp expect actual &&
			cat >expect <<-EOF &&
			$blob_sizes.1.inflated_size=16
			$blob_sizes.2.inflated_size=16
			$blob_sizes.3.inflated_size=0
			EOF
			sed -n "/^$blob_sizes\..*\.inflated_size=/p" \
				out >actual &&
			test_cmp expect actual &&
			printf "%s\n" "$big" "$tied" >expect-unsorted &&
			sort expect-unsorted >expect &&
			sed -n "s/^$blob_sizes\.[12]\.oid=//p" \
				out >actual-unsorted &&
			sort actual-unsorted >actual &&
			test_cmp expect actual &&
			test_grep "^$blob_sizes.3.oid=$empty_blob$" out &&
			test_grep ! "^$blob_sizes.4." out &&
			for rank in 1 2 3
			do
				oid=$(sed -n \
					"s/^$blob_sizes.$rank.oid=//p" out) &&
				path=$(sed -n \
					"s/^$blob_sizes.$rank.path=//p" out) &&
				test_grep -F -x "$oid $path" allowed-paths ||
				return 1
			done &&

			git repo structure --format=nul "$@" >nul &&
			tr "\012\000" "=\012" <nul >decoded &&
			test_cmp out decoded &&
			git repo structure "$@" >table &&
			sed -n "/^| Largest commits by parent count /,/^$/p" \
				table >parents &&
			test_grep "(commit $merge) (main) *\[1\] | *2 *|$" \
				parents &&
			sed -n "/^| Largest blobs by size /,/^$/p" \
				table >blobs &&
			test_grep "^| 1: .* \[1\] | *16 B *|$" blobs ||
			return 1
		done &&

		git repo structure --format=lines "$@" \
			--ref-filter=refs/heads/empty >out &&
		test_grep "^$commit_parents.1.parents=0$" out &&
		test_grep ! "^$commit_parents.2." out &&
		test_grep "^$tree_entries.1.entries=0$" out &&
		test_grep ! "^$tree_entries.2." out &&
		test_grep ! "^$blob_sizes." out &&
		git repo structure --format=lines "$@" \
			--ref-filter=refs/heads/missing >out &&
		test_grep ! "\.largest\." out
	)
'

test_expect_success 'largest object paths stay with their ranked objects' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		mkdir dir &&
		i=0 &&
		>objects &&
		for size in 1 9 2 8 3 7
		do
			i=$((i + 1)) &&
			test-tool genzeros "$size" >"dir/$i" &&
			oid=$(git hash-object -w "dir/$i") &&
			printf "%s %s %s\n" "$size" "$oid" "dir/$i" \
				>>objects || return 1
		done &&
		git add dir &&
		test_tick &&
		git commit -m paths &&
		dir=$(git rev-parse HEAD:dir) &&
		dir_size=$(git cat-file -s "$dir") &&
		entries=objects.trees.largest.by_entries &&
		sizes=objects.trees.largest.by_size &&
		blobs=objects.blobs.largest.by_size &&
		sort -rn objects >sorted &&
		for limit in 1 2 4
		do
			cat >expect <<-EOF &&
			$entries.1.entries=6
			$entries.1.oid=$dir
			$entries.1.path=dir/
			$sizes.1.inflated_size=$dir_size
			$sizes.1.oid=$dir
			$sizes.1.path=dir/
			EOF
			sed -n "1,${limit}p" sorted >selected &&
			rank=0 &&
			while read -r size oid path
			do
				rank=$((rank + 1)) &&
				key=$blobs.$rank &&
				printf "%s=%s\n" \
					"$key.inflated_size" "$size" \
					"$key.oid" "$oid" \
					"$key.path" "$path" >>expect ||
				return 1
			done <selected &&
			git repo structure --format=lines --tree-entries=1 \
				--tree-sizes=1 --blob-sizes="$limit" >out &&
			sed -n "/\.largest\./p" out >actual &&
			test_cmp expect actual || return 1
		done
	)
'

test_expect_success 'largest object paths are quoted except in NUL output' '
	test_when_finished "rm -rf repo" &&
	git init --initial-branch=main repo &&
	(
		cd repo &&
		test-tool genzeros 16 >blob &&
		blob=$(git hash-object -w blob) &&
		printf "100644 blob %s\tfile\0" "$blob" >tree-input &&
		dir=$(git mktree -z <tree-input) &&
		name=$(printf "d\011\012\042\134x") &&
		printf "040000 tree %s\t%s\0" "$dir" "$name" >tree-input &&
		root=$(git mktree -z <tree-input) &&
		commit=$(git commit-tree "$root" -m paths) &&
		git update-ref refs/heads/main "$commit" &&
		root_size=$(git cat-file -s "$root") &&
		dir_size=$(git cat-file -s "$dir") &&
		trees=objects.trees.largest.by_size &&
		blobs=objects.blobs.largest.by_size &&
		set -- --tree-sizes=2 --blob-sizes=1 &&

		cat >expect <<-\EOF &&
		objects.trees.largest.by_size.1.path=
		objects.trees.largest.by_size.2.path="d\t\n\"\\x/"
		objects.blobs.largest.by_size.1.path="d\t\n\"\\x/file"
		EOF
		git repo structure --format=lines "$@" >out &&
		sed -n "/\.largest\..*\.path=/p" out >actual &&
		test_cmp expect actual &&

		cat >patterns <<-\EOF &&
		2: "d\t\n\"\\x/"
		1: "d\t\n\"\\x/file"
		EOF
		git repo structure "$@" >table &&
		while IFS= read -r pattern
		do
			test_grep -F "$pattern" table || return 1
		done <patterns &&

		git repo structure --format=nul >expect &&
		printf "%s\n%s\0" \
			"$trees.1.inflated_size" "$root_size" \
			"$trees.1.oid" "$root" \
			"$trees.1.path" "" \
			"$trees.2.inflated_size" "$dir_size" \
			"$trees.2.oid" "$dir" \
			"$trees.2.path" "$name/" \
			"$blobs.1.inflated_size" 16 \
			"$blobs.1.oid" "$blob" \
			"$blobs.1.path" "$name/file" >>expect &&
		git repo structure --format=nul "$@" >actual &&
		test_cmp expect actual
	)
'

test_expect_success 'ranked revision names are batched and use all refs' '
	test_when_finished "rm -rf repo" &&
	git init --initial-branch=main repo &&
	(
		cd repo &&
		test_commit --no-tag one file &&
		git tag -a -m tag v1 &&
		name=tags/v1^0 &&
		key=objects.commits.largest &&
		set -- --commit-parents=4 --commit-sizes=4 \
			--tree-entries=4 --tree-sizes=4 --blob-sizes=4 &&
		GIT_TRACE2_EVENT="$PWD/trace" git repo structure \
			--format=lines --progress \
			--ref-filter=refs/heads/main "$@" >out 2>err &&
		printf "%s=%s\n" \
			"$key.by_parents.1.name_rev" "$name" \
			"$key.by_size.1.name_rev" "$name" >expect &&
		sed -n "/\.name_rev=/p" out >actual &&
		test_cmp expect actual &&
		test_grep "^references.tags.count=0$" out &&
		test_grep "Resolving revision names" err &&
		grep "child_start.*\"name-rev\"" trace >children &&
		test_line_count = 1 children &&

		GIT_TRACE2_EVENT="$PWD/default-trace" \
			git repo structure >out &&
		test_grep ! "child_start.*\"name-rev\"" default-trace &&
		GIT_TRACE2_EVENT="$PWD/tree-trace" git repo structure \
			--tree-entries=4 --tree-sizes=4 --blob-sizes=4 >out &&
		test_grep ! "child_start.*\"name-rev\"" tree-trace
	)
'

test_expect_success 'ranked revision names quote text but preserve NUL data' '
	test_when_finished "rm -rf repo" &&
	name=$(printf "q\042\303\251") &&
	git init --ref-format=reftable --initial-branch="$name" repo &&
	(
		cd repo &&
		test_commit --no-tag one file &&
		oid=$(git rev-parse HEAD) &&
		key=objects.commits.largest.by_parents &&
		cat >expect <<-\EOF &&
		objects.commits.largest.by_parents.1.name_rev="q\"\303\251"
		EOF
		git -c core.quotePath=true repo structure \
			--commit-parents=2 --format=lines >out &&
		sed -n "/\.name_rev=/p" out >actual &&
		test_cmp expect actual &&
		cat >pattern <<-\EOF &&
		("q\"\303\251")
		EOF
		git -c core.quotePath=true repo structure \
			--commit-parents=2 >table &&
		grep -F -f pattern table >found &&
		test_line_count = 1 found &&

		printf "%s=\042q\134\042\303\251\042\n" \
			"$key.1.name_rev" >expect &&
		git -c core.quotePath=false repo structure \
			--commit-parents=2 --format=lines >out &&
		sed -n "/\.name_rev=/p" out >actual &&
		test_cmp expect actual &&

		git repo structure --format=nul >expect &&
		printf "%s\n%s\0" \
			"$key.1.parents" 0 \
			"$key.1.oid" "$oid" \
			"$key.1.commit_oid" "$oid" \
			"$key.1.name_rev" "$name" >>expect &&
		git repo structure --commit-parents=2 --format=nul >actual &&
		test_cmp expect actual
	)
'

test_expect_success 'revision-name failures leave other statistics intact' '
	test_when_finished "rm -rf repo" &&
	git init --initial-branch=main repo &&
	(
		cd repo &&
		test_commit --no-tag one file &&
		oid=$(git rev-parse HEAD) &&
		set -- --commit-parents=3 --commit-sizes=3 --format=lines &&
		git repo structure "$@" >original &&
		sed "/\.name_rev=/d" original >expect &&
		printf "%s\n" "$oid" "$oid" >expect-input &&
		mkdir mock &&
		write_script mock/git <<-\EOF &&
		if test "$*" != "name-rev --name-only --annotate-stdin"
		then
			echo "unexpected command: $*" >&2
			exit 1
		fi
		cat >name-rev-input || exit 1
		case "$NAME_REV_MODE" in
		fail) exit 1 ;;
		short) printf "first\n" ;;
		extra) printf "first\nsecond\nthird\n" ;;
		unterminated) printf "first\nsecond" ;;
		nul) printf "first\0ignored\nsecond\n" ;;
		empty) printf "first\n\n" ;;
		raw) cat name-rev-input ;;
		crlf) printf "first\r\nsecond\r\n" ;;
		esac
		EOF
		for mode in fail short extra unterminated nul empty
		do
			NAME_REV_MODE=$mode git --exec-path="$PWD/mock" \
				repo structure "$@" >out 2>err &&
			test_cmp expect-input name-rev-input &&
			test_cmp expect out &&
			case "$mode" in
			fail)
				test_grep "could not resolve revision names" err
				;;
			*)
				test_grep "unexpected output.*name-rev" err
				;;
			esac || return 1
		done &&

		key=objects.commits.largest &&
		for mode in raw crlf
		do
			NAME_REV_MODE=$mode git --exec-path="$PWD/mock" \
				repo structure "$@" >out 2>err &&
			test_must_be_empty err &&
			test_cmp expect-input name-rev-input &&
			sed "/\.name_rev=/d" out >actual &&
			test_cmp expect actual &&
			case "$mode" in
			raw) first=$oid second=$oid ;;
			crlf) first=first second=second ;;
			esac &&
			printf "%s=%s\n" \
				"$key.by_parents.1.name_rev" "$first" \
				"$key.by_size.1.name_rev" "$second" \
				>expect-names &&
			sed -n "/\.name_rev=/p" out >actual &&
			test_cmp expect-names actual || return 1
		done
	)
'

for spec in \
	"commit-parents showCommitParents commits by_parents parents" \
	"commit-sizes showCommitSizes commits by_size inflated_size" \
	"tree-entries showTreeEntries trees by_entries entries" \
	"tree-sizes showTreeSizes trees by_size inflated_size" \
	"blob-sizes showBlobSizes blobs by_size inflated_size"
do
	set -- $spec
	option=$1 config=$2 type=$3 dimension=$4 metric=$5

	test_expect_success "--$option is opt-in and overrides its config" '
		test_when_finished "rm -rf repo" &&
		git init --initial-branch=main repo &&
		(
			cd repo &&
			test_commit --no-tag one file &&
			case "$type" in
			commits) oid=$(git rev-parse HEAD) ;;
			trees) oid=$(git rev-parse HEAD^{tree}) ;;
			blobs) oid=$(git rev-parse HEAD:file) ;;
			esac &&
			case "$metric" in
			parents) value=0 ;;
			entries) value=1 ;;
			inflated_size) value=$(git cat-file -s "$oid") ;;
			esac &&
			key=objects.$type.largest.$dimension &&
			cat >expect <<-EOF &&
			$key.1.$metric=$value
			$key.1.oid=$oid
			EOF
			case "$type" in
			commits)
				printf "%s=%s\n" "$key.1.commit_oid" "$oid" \
					"$key.1.name_rev" main >>expect
				;;
			trees) echo "$key.1.path=" >>expect ;;
			blobs) echo "$key.1.path=file" >>expect ;;
			esac &&
			git repo structure --format=lines >default &&
			test_grep ! "\.largest\." default &&
			git repo structure --format=lines "--$option=3" >out &&
			sed -n "/\.largest\./p" out >actual &&
			test_cmp expect actual &&
			git repo structure --format=nul "--$option=3" >nul &&
			tr "\012\000" "=\012" <nul >decoded &&
			test_cmp out decoded &&
			git repo structure "--$option=3" >table &&
			case "$type" in
			commits) test_grep -F "(commit $oid) (main)" table ;;
			*) test_grep ! -F "(commit " table ;;
			esac &&
			git -c repo.structure.$config=3 repo structure \
				--format=lines >configured &&
			test_cmp out configured &&
			git -c repo.structure.$config=3 repo structure \
				--format=lines "--$option=0" >disabled &&
			test_cmp default disabled &&
			git -c repo.structure.$config=0 repo structure \
				--format=lines "--$option=3" >override &&
			test_cmp out override &&

			test_commit --no-tag two other "larger content" &&
			git -c repo.structure.$config=1 repo structure \
				--format=lines >limit-one &&
			git -c repo.structure.$config=2 repo structure \
				--format=lines >limit-two &&
			git repo structure --format=lines "--$option=2" \
				>expected-two &&
			test_cmp expected-two limit-two &&
			sed -n "/\.largest\..*\.oid=/p" limit-one >oids &&
			test_line_count = 1 oids &&
			sed -n "/\.largest\..*\.oid=/p" limit-two >oids &&
			test_line_count = 2 oids &&

			test_must_fail git repo structure "--$option=-1" \
				2>err &&
			test_grep "must be non-negative" err &&
			test_must_fail git -c repo.structure.$config=-1 \
				repo structure 2>err &&
			test_grep "must be non-negative" err &&
			test_must_fail git repo structure "--$option=bad" \
				2>err
		)
	'
done

test_expect_success 'largest object lists are empty in an empty repository' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	(
		cd repo &&
		git repo structure >expect &&
		git repo structure --commit-parents=3 --commit-sizes=3 \
			--tree-entries=3 --tree-sizes=3 --blob-sizes=3 \
			>actual &&
		test_cmp expect actual
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
