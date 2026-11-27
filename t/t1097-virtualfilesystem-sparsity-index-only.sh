#!/bin/sh

test_description='sparse-checkout changes only the index under a VFS

A virtual file system owns the working tree. With cone mode and
index.sparse set to true, "git sparse-checkout reapply" must change only
the index. It must not check out or remove files, also when it expands a
sparse directory whose files the virtual file system reports as modified
or deleted.'

GIT_TEST_SPLIT_INDEX=0
GIT_TEST_SPARSE_INDEX=

. ./test-lib.sh

# Write the cone-mode patterns for the directories "$2"... to the
# sparse-checkout file of repository "$1".
write_cone () {
	repo=$1 &&
	shift &&
	printf "/*\n!/*/\n" >"$repo/.git/info/sparse-checkout" &&
	for d in "$@"
	do
		printf "/%s/\n" "$d" >>"$repo/.git/info/sparse-checkout" ||
		return 1
	done
}

# Create repository "$1" with the cone "in" and a sparse index, in which
# "out/" and "out2/" are sparse directories.
create_repo () {
	git init "$1" &&
	(
		cd "$1" &&
		mkdir -p in out out2/deep &&
		for f in r in/a out/f1 out/f2 out2/deep/g1 out2/deep/g2
		do
			echo "$f" >$f || return 1
		done &&
		git add . &&
		git commit -m init &&
		git sparse-checkout set in &&
		git config index.sparse true
	)
}

# Enable a virtual file system in repository "$1". The hook reports the
# paths in .git/vfs-paths, one per line. A virtual file system shows all
# files in the working tree, so put the out-of-cone files back on disk.
enable_vfs () {
	write_script "$1/.git/hooks/virtualfilesystem" <<-\EOF &&
	tr "\n" "\0" <.git/vfs-paths
	EOF
	printf "r\nin/a\n" >"$1/.git/vfs-paths" &&
	(
		cd "$1" &&
		mkdir -p out out2/deep &&
		for f in out/f1 out/f2 out2/deep/g1 out2/deep/g2
		do
			echo "$f" >$f || return 1
		done
	) &&
	git -C "$1" config core.virtualfilesystem \
		.git/hooks/virtualfilesystem &&
	git -C "$1" sparse-checkout reapply &&
	git -C "$1" ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	S out/
	S out2/
	H r
	EOF
	test_cmp expect actual
}

# Write a list of the files and directories in the working tree of
# repository "$1", with the contents of the files, to "$2".
snapshot_worktree () {
	(
		cd "$1" &&
		find . -path ./.git -prune -o -print | sort |
		while read -r f
		do
			if test -f "$f"
			then
				echo "$f $(git hash-object "$f")"
			else
				echo "$f"
			fi || return 1
		done
	) >"$2"
}

test_expect_success 'widen keeps a deleted file deleted' '
	create_repo deleted &&
	enable_vfs deleted &&
	rm deleted/out/f1 &&
	echo out/f1 >>deleted/.git/vfs-paths &&

	write_cone deleted in out &&
	git -C deleted sparse-checkout reapply &&

	test_path_is_missing deleted/out/f1 &&
	git -C deleted ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	H out/f1
	S out/f2
	S out2/
	H r
	EOF
	test_cmp expect actual &&
	git -C deleted status --porcelain --untracked-files=no >actual &&
	echo " D out/f1" >expect &&
	test_cmp expect actual
'

test_expect_success 'widen keeps the content of a modified file' '
	create_repo modified &&
	enable_vfs modified &&
	echo changed >modified/out/f2 &&
	echo out/f2 >>modified/.git/vfs-paths &&

	write_cone modified in out &&
	git -C modified sparse-checkout reapply 2>err &&

	test_must_be_empty err &&
	echo changed >expect &&
	test_cmp expect modified/out/f2 &&
	git -C modified status --porcelain --untracked-files=no >actual &&
	echo " M out/f2" >expect &&
	test_cmp expect actual
'

test_expect_success 'reapply does not change the working tree' '
	create_repo nochange &&
	enable_vfs nochange &&
	rm nochange/out/f1 &&
	echo changed >nochange/out2/deep/g2 &&
	printf "out/f1\nout2/deep/g2\n" >>nochange/.git/vfs-paths &&
	snapshot_worktree nochange before &&

	write_cone nochange in out out2 &&
	git -C nochange sparse-checkout reapply &&

	snapshot_worktree nochange after &&
	test_cmp before after &&
	git -C nochange ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	H out/f1
	S out/f2
	S out2/deep/g1
	H out2/deep/g2
	H r
	EOF
	test_cmp expect actual
'

test_expect_success 'add and disable keep deleted files deleted' '
	create_repo callers &&
	enable_vfs callers &&
	rm callers/out/f1 callers/out2/deep/g1 &&
	printf "out/f1\nout2/deep/g1\n" >>callers/.git/vfs-paths &&
	snapshot_worktree callers before &&

	git -C callers sparse-checkout add out &&
	test_path_is_missing callers/out/f1 &&
	git -C callers sparse-checkout disable &&
	test_path_is_missing callers/out2/deep/g1 &&

	snapshot_worktree callers after &&
	test_cmp before after &&
	git -C callers status --porcelain --untracked-files=no >actual &&
	cat >expect <<-\EOF &&
	 D out/f1
	 D out2/deep/g1
	EOF
	test_cmp expect actual
'

test_expect_success 'without a virtual file system, widen checks out files' '
	create_repo novfs &&
	git -C novfs sparse-checkout reapply &&
	test_path_is_missing novfs/out &&

	write_cone novfs in out &&
	git -C novfs sparse-checkout reapply &&

	echo out/f1 >expect &&
	test_cmp expect novfs/out/f1 &&
	echo out/f2 >expect &&
	test_cmp expect novfs/out/f2 &&
	git -C novfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	H out/f1
	H out/f2
	S out2/
	H r
	EOF
	test_cmp expect actual
'

test_done
