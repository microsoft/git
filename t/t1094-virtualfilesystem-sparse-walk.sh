#!/bin/sh

test_description='sparse index and virtual file system: working-tree walk

A virtual file system projects files on disk inside directories that a
sparse index collapses into sparse-directory entries. The working-tree walk
must answer its index lookups for those paths without an expansion of the
index, and give the same results as an expanded index.
'

# A split index cannot be sparse.
GIT_TEST_SPLIT_INDEX=0
GIT_TEST_SPARSE_INDEX=

. ./test-lib.sh

# Run a command in "repo" with the virtual file system and record trace2
# events in trace-vfs.txt.
run_vfs () {
	rm -f trace-vfs.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace-vfs.txt" GIT_TRACE2_EVENT_NESTING=10 \
		git -C repo "$@"
}

# Run a command in "full", which has the same working tree and sparse-checkout
# definition as "repo" but a full index and no virtual file system.
run_full () {
	git -C full -c sparse.expectFilesOutsideOfPatterns=true "$@"
}

# Run a command in "repo" without the virtual file system. The out-of-cone
# files stay on disk, so the walk visits them, and its index lookups use
# the code that expands a sparse index.
run_no_vfs () {
	rm -f trace-no-vfs.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace-no-vfs.txt" \
	GIT_TRACE2_EVENT_NESTING=10 \
		git -C repo -c core.virtualfilesystem= \
			-c sparse.expectFilesOutsideOfPatterns=true "$@"
}

ensure_not_expanded () {
	test_region ! index ensure_full_index "$1" &&
	test_grep ! "expansion-reason" "$1"
}

ensure_index_is_sparse () {
	git -C repo -c core.virtualfilesystem= \
		-c sparse.expectFilesOutsideOfPatterns=true \
		ls-files --sparse >sparse-entries &&
	test_grep "^out/$" sparse-entries
}

# Run a command with the virtual file system over a sparse index, and in
# the full-index repository, then compare. The virtual file system run
# must not expand the index.
test_vfs_matches_full () {
	run_vfs "$@" >actual-vfs &&
	ensure_not_expanded trace-vfs.txt &&
	ensure_index_is_sparse &&
	run_full "$@" >actual-full &&
	test_cmp actual-full actual-vfs
}

# Rename the directory $1 to $2, a name that differs only in case, in each
# repository that follows them.
rename_case () {
	from=$1 &&
	to=$2 &&
	shift 2 &&
	for r in "$@"
	do
		mv "$r/$from" "$r/$from.tmp" &&
		mv "$r/$from.tmp" "$r/$to" || return 1
	done
}

# Put the out-of-cone files back on disk, as a virtual file system does,
# and add untracked and ignored files inside "out/". Leave
# out/deep/.gitignore absent, so that the walk reads it from the index.
populate_out_of_cone () {
	mkdir -p $1/out/deep/sub $1/out/other &&
	for f in out/a out/deep/a out/deep/sub/a \
		 out/other/a out/other/.gitignore
	do
		git -C $1 show HEAD:$f >$1/$f || return 1
	done &&
	echo new >$1/out/new.txt &&
	echo new >$1/out/deep/new.txt &&
	echo new >$1/out/deep/sub/new.txt &&
	echo new >$1/out/deep/x.ignored &&
	mkdir -p $1/out/deep/ignored-dir $1/out/untracked-dir &&
	echo new >$1/out/deep/ignored-dir/y.ignored &&
	echo new >$1/out/untracked-dir/new.txt &&
	echo new >$1/out/other/z.skip
}

test_expect_success 'setup' '
	git init repo &&
	mkdir -p repo/in repo/out/deep/sub repo/out/other &&
	echo a >repo/a &&
	echo a >repo/in/a &&
	echo a >repo/out/a &&
	echo a >repo/out/deep/a &&
	echo a >repo/out/deep/sub/a &&
	echo a >repo/out/other/a &&
	echo "*.ignored" >repo/out/deep/.gitignore &&
	echo "*.skip" >repo/out/other/.gitignore &&
	git -C repo add . &&
	git -C repo commit -m initial &&
	git clone repo full &&

	git -C repo sparse-checkout set --cone --sparse-index in &&
	test_path_is_missing repo/out &&
	populate_out_of_cone repo &&

	git -C full sparse-checkout set --cone --no-sparse-index in &&
	test_path_is_missing full/out &&
	populate_out_of_cone full &&

	# List "out/" as a whole, so the walk visits it. This name is the
	# exact name of the sparse-directory entry, so the hook does not make
	# git expand the index.
	write_script repo/.git/hooks/virtualfilesystem <<-\EOF &&
	printf "a\0in/\0out/\0"
	EOF
	git -C repo config core.virtualfilesystem \
		.git/hooks/virtualfilesystem &&
	ensure_index_is_sparse
'

test_expect_success 'status does not expand the index' '
	run_vfs status --porcelain=v1 >actual &&
	ensure_not_expanded trace-vfs.txt &&
	ensure_index_is_sparse &&
	cat >expect <<-\EOF &&
	?? out/deep/new.txt
	?? out/deep/sub/new.txt
	?? out/new.txt
	?? out/untracked-dir/
	EOF
	test_cmp expect actual
'

test_expect_success 'status -uall does not expand the index' '
	run_vfs status --porcelain=v1 -uall >actual &&
	ensure_not_expanded trace-vfs.txt &&
	cat >expect <<-\EOF &&
	?? out/deep/new.txt
	?? out/deep/sub/new.txt
	?? out/new.txt
	?? out/untracked-dir/new.txt
	EOF
	test_cmp expect actual
'

for ignorecase in false true
do
	for args in "" "-uall" "--ignored" "--ignored -uall" \
		    "--ignored=matching"
	do
		test_expect_success "status $args (ignoreCase=$ignorecase)" "
			test_vfs_matches_full -c core.ignoreCase=$ignorecase \
				status --porcelain=v1 $args
		"
	done

	for args in "" "-d" "-d -x" "-d -X"
	do
		test_expect_success "clean -n $args (ignoreCase=$ignorecase)" "
			test_vfs_matches_full -c core.ignoreCase=$ignorecase \
				clean -n $args
		"
	done
done

test_expect_success 'clean -n -d -x lists only untracked paths' '
	run_vfs clean -n -d -x >actual &&
	ensure_not_expanded trace-vfs.txt &&
	cat >expect <<-\EOF &&
	Would remove out/deep/ignored-dir/
	Would remove out/deep/new.txt
	Would remove out/deep/sub/new.txt
	Would remove out/deep/x.ignored
	Would remove out/new.txt
	Would remove out/other/z.skip
	Would remove out/untracked-dir/
	EOF
	test_cmp expect actual
'

# Spell a tracked directory with a different case on disk. With
# core.ignoreCase, a full index treats it as tracked, so "git clean"
# must not offer to remove it.
test_expect_success 'directory with a different case on disk (ignoreCase)' '
	rename_case out/other out/OTHER repo full &&
	test_when_finished "rename_case out/OTHER out/other repo full" &&
	test_vfs_matches_full -c core.ignoreCase=true \
		status --porcelain=v1 -uall &&
	test_vfs_matches_full -c core.ignoreCase=true clean -n -d &&
	test_grep ! OTHER actual-vfs
'

test_expect_success 'sparse directory with a different case on disk (ignoreCase)' '
	rename_case out OUT repo full &&
	test_when_finished "rename_case OUT out repo full" &&
	test_vfs_matches_full -c core.ignoreCase=true \
		status --porcelain=v1 -uall &&
	test_grep ! "OUT/a$" actual-vfs &&
	test_vfs_matches_full -c core.ignoreCase=true clean -n -d &&
	test_grep "OUT/new.txt" actual-vfs &&
	test_grep ! "OUT/a$" actual-vfs &&
	test_grep ! "OUT/deep/$" actual-vfs
'

# Here "out/" is in the cone as a parent directory, and "out/deep/" is the
# sparse-directory entry. Both have a different case on disk.
test_expect_success 'nested sparse directory with a different case on disk' '
	test_when_finished "rm -rf repo2 full2" &&
	git clone full repo2 &&
	git clone full full2 &&
	git -C repo2 sparse-checkout set --cone --sparse-index in out/other &&
	git -C full2 sparse-checkout set --cone --no-sparse-index in out/other &&
	populate_out_of_cone repo2 &&
	populate_out_of_cone full2 &&
	write_script repo2/.git/hooks/virtualfilesystem <<-\EOF &&
	printf "a\0in/\0out/a\0out/new.txt\0out/deep/\0out/other/\0"
	printf "out/untracked-dir/\0"
	EOF
	git -C repo2 config core.virtualfilesystem \
		.git/hooks/virtualfilesystem &&
	rename_case out OUT repo2 full2 &&
	rename_case OUT/deep OUT/Deep repo2 full2 &&

	for args in "status --porcelain=v1 -uall" "clean -n -d"
	do
		rm -f trace-vfs.txt &&
		GIT_TRACE2_EVENT="$(pwd)/trace-vfs.txt" \
		GIT_TRACE2_EVENT_NESTING=10 \
			git -C repo2 -c core.ignoreCase=true $args >actual-vfs &&
		ensure_not_expanded trace-vfs.txt &&
		git -C full2 -c sparse.expectFilesOutsideOfPatterns=true \
			-c core.ignoreCase=true $args >actual-full &&
		test_cmp actual-full actual-vfs || return 1
	done &&
	test_grep "OUT/Deep/new.txt" actual-vfs &&
	test_grep ! "OUT/Deep/a$" actual-vfs &&
	test_grep ! "OUT/Deep/$" actual-vfs &&
	git -C repo2 -c core.virtualfilesystem= \
		-c sparse.expectFilesOutsideOfPatterns=true \
		ls-files --sparse >sparse-entries &&
	test_grep "^out/deep/$" sparse-entries
'

test_expect_success 'status with the untracked cache' '
	test_vfs_matches_full -c core.untrackedCache=true \
		status --porcelain=v1 &&
	test_vfs_matches_full -c core.untrackedCache=true \
		status --porcelain=v1 -uall
'

# With a glob pathspec, "git add --ignore-missing" asks is_excluded() for
# the type of the path, which looks up the path in the index.
test_expect_success 'add --ignore-missing of an ignored path' '
	rm -f trace-vfs.txt &&
	test_must_fail env GIT_TRACE2_EVENT="$(pwd)/trace-vfs.txt" \
		GIT_TRACE2_EVENT_NESTING=10 \
		git -C repo add --dry-run --ignore-missing \
		":(glob)out/deep/x.ignored" >actual-vfs 2>err-vfs &&
	ensure_not_expanded trace-vfs.txt &&
	ensure_index_is_sparse &&
	test_must_fail git -C full -c sparse.expectFilesOutsideOfPatterns=true \
		add --dry-run --ignore-missing \
		":(glob)out/deep/x.ignored" >actual-full 2>err-full &&
	test_cmp actual-full actual-vfs &&
	test_cmp err-full err-vfs &&
	test_grep "ignored by one of your .gitignore files" err-vfs &&
	test_grep "out/deep/x.ignored" err-vfs
'

test_expect_success 'an unreadable tree in a sparse directory is an error' '
	test_when_finished "rm -rf broken" &&
	cp -R repo broken &&
	tree=$(git -C broken rev-parse HEAD:out/deep) &&
	rm broken/.git/objects/$(test_oid_to_path $tree) &&
	test_must_fail git -C broken clean -n -d >out 2>err &&
	test_grep "unable to read tree $tree" err &&
	test_grep ! "Would remove" out
'

test_expect_success 'without a virtual file system, the walk still expands' '
	run_no_vfs status --porcelain=v1 >actual &&
	test_grep "found parent dir .out/." trace-no-vfs.txt &&
	run_full status --porcelain=v1 >expect &&
	test_cmp expect actual
'

test_done
