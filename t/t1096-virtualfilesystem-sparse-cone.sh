#!/bin/sh

test_description='cone-mode sparse-checkout under a virtual file system

Without a sparse index, a virtual file system makes
path_in_sparse_checkout() report every path as inside the
sparse-checkout, so convert_to_sparse() never collapses a directory.
When the repository uses cone mode and sets index.sparse to true, the
cone patterns decide. The default value of index.sparse does not count.
Otherwise the behavior must not change.'

GIT_TEST_SPLIT_INDEX=0
GIT_TEST_SPARSE_INDEX=

. ./test-lib.sh

# Fail if the trace in "$1" shows that the index was expanded.
test_no_index_expansion () {
	test_region ! index ensure_full_index "$1" &&
	test_region ! index expand_index "$1" &&
	test_grep ! expansion-reason "$1"
}

# Create a cone-mode repository "$1" with the cone "in" and a full index.
create_cone_repo () {
	git init "$1" &&
	(
		cd "$1" &&
		mkdir -p in out &&
		for f in r in/a out/f1 out/f2
		do
			echo "$f" >$f || return 1
		done &&
		git add . &&
		git commit -m init &&
		git sparse-checkout set in &&
		git config index.sparse false &&
		git sparse-checkout reapply
	)
}

# Enable a virtual file system in repository "$1". The hook reports the
# paths in .git/vfs-paths, one per line. A virtual file system shows all
# files in the working tree, so put the out-of-cone files back on disk.
enable_vfs () {
	write_script "$1/.git/hooks/virtualfilesystem" <<-\EOF &&
	tr "\n" "\0" <.git/vfs-paths
	EOF
	cat >"$1/.git/vfs-paths" <<-\EOF &&
	r
	in/a
	EOF
	mkdir "$1/out" &&
	echo out/f1 >"$1/out/f1" &&
	echo out/f2 >"$1/out/f2" &&
	git -C "$1" config core.virtualfilesystem .git/hooks/virtualfilesystem
}

# Fail if a file of repository "$1" is missing from the working tree.
test_all_files_exist () {
	test_path_is_file "$1/r" &&
	test_path_is_file "$1/in/a" &&
	test_path_is_file "$1/out/f1" &&
	test_path_is_file "$1/out/f2"
}

test_expect_success 'setup' '
	create_cone_repo vfs &&
	enable_vfs vfs &&
	create_cone_repo novfs
'

test_expect_success 'nothing collapses with index.sparse false' '
	git -C vfs sparse-checkout reapply &&
	test_all_files_exist vfs &&
	git -C vfs ls-files --sparse >actual &&
	cat >expect <<-\EOF &&
	in/a
	out/f1
	out/f2
	r
	EOF
	test_cmp expect actual
'

test_expect_success 'nothing collapses with the default index.sparse' '
	git -C vfs config --unset-all index.sparse &&
	test_might_fail git -C vfs config --worktree --unset-all index.sparse &&
	test_must_fail git -C vfs config index.sparse &&
	git -C vfs sparse-checkout reapply &&
	test_must_fail git -C vfs config index.sparse &&
	test_all_files_exist vfs &&
	git -C vfs ls-files --sparse >actual &&
	cat >expect <<-\EOF &&
	in/a
	out/f1
	out/f2
	r
	EOF
	test_cmp expect actual
'

test_expect_success 'out-of-cone directory collapses with index.sparse true' '
	git -C vfs config index.sparse true &&
	git -C vfs sparse-checkout reapply &&
	test_all_files_exist vfs &&
	git -C vfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	S out/
	H r
	EOF
	test_cmp expect actual
'

test_expect_success 'status keeps the index collapsed' '
	test_when_finished "git -C vfs checkout -- in/a" &&
	echo changed >>vfs/in/a &&
	rm -f trace.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace.txt" \
		git -C vfs status --porcelain --untracked-files=no >actual &&
	test_no_index_expansion trace.txt &&
	echo " M in/a" >expect &&
	test_cmp expect actual &&

	git -C vfs ls-files --sparse >files &&
	test_grep "^out/$" files
'

test_expect_success 'widening the cone keeps reported files' '
	test_when_finished "git -C vfs sparse-checkout set in" &&
	git -C vfs sparse-checkout add out &&
	test_all_files_exist vfs &&
	git -C vfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	S out/f1
	S out/f2
	H r
	EOF
	test_cmp expect actual
'

test_expect_success 'reapply on a collapsed index does not expand it' '
	test_when_finished "cp vfs/.git/vfs-paths.bak vfs/.git/vfs-paths" &&
	cp vfs/.git/vfs-paths vfs/.git/vfs-paths.bak &&
	echo out/f1 >>vfs/.git/vfs-paths &&
	rm -f trace.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace.txt" \
		git -C vfs sparse-checkout reapply &&
	test_region ! index ensure_full_index trace.txt &&
	test_grep ! expansion-reason trace.txt &&
	test_all_files_exist vfs &&
	git -C vfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	S out/
	H r
	EOF
	test_cmp expect actual
'

test_expect_success 'directory with a reported path does not collapse' '
	test_when_finished "cp vfs/.git/vfs-paths.bak vfs/.git/vfs-paths" &&
	cp vfs/.git/vfs-paths vfs/.git/vfs-paths.bak &&
	git -C vfs config index.sparse false &&
	git -C vfs sparse-checkout reapply &&
	echo out/f1 >>vfs/.git/vfs-paths &&
	git -C vfs config index.sparse true &&
	git -C vfs sparse-checkout reapply &&
	test_all_files_exist vfs &&
	git -C vfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	H out/f1
	S out/f2
	H r
	EOF
	test_cmp expect actual
'

test_expect_success 'non-cone sparse-checkout under a virtual file system' '
	git -C vfs sparse-checkout set --no-cone "/in/" &&
	git -C vfs config index.sparse true &&
	git -C vfs sparse-checkout reapply &&
	test_all_files_exist vfs &&
	git -C vfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	S out/f1
	S out/f2
	H r
	EOF
	test_cmp expect actual
'

test_expect_success 'without a virtual file system, cone mode is unchanged' '
	git -C novfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	S out/f1
	S out/f2
	H r
	EOF
	test_cmp expect actual &&

	git -C novfs config index.sparse true &&
	git -C novfs sparse-checkout reapply &&
	git -C novfs ls-files -t --sparse >actual &&
	cat >expect <<-\EOF &&
	H in/a
	S out/
	H r
	EOF
	test_cmp expect actual &&

	rm -f trace.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace.txt" \
		git -C novfs status --porcelain >actual &&
	test_no_index_expansion trace.txt &&
	test_must_be_empty actual
'

test_done
