#!/bin/sh

test_description='virtual file system does not expand a sparse index

apply_virtualfilesystem() runs on every index read. It sets the
skip-worktree bit on every index entry, then clears it for the paths that
the virtual file system hook reports. With a sparse index, a reported path
inside a sparse-directory entry must not expand the index, and the
sparse-directory entry must keep its skip-worktree bit.'

GIT_TEST_SPLIT_INDEX=0
GIT_TEST_SPARSE_INDEX=

. ./test-lib.sh

# Fail if the trace in "$1" shows that the index was expanded.
test_no_index_expansion () {
	test_region ! index ensure_full_index "$1" &&
	test_region ! index expand_index "$1" &&
	test_grep ! expansion-reason "$1"
}

# The hook reports the paths in .git/vfs-paths, one per line.
test_expect_success 'setup' '
	git init repo &&
	(
		cd repo &&
		mkdir -p in/deeper in/other out/sub &&
		for f in r in/a in/deeper/a in/other/a out/f1 out/f2 out/sub/f
		do
			echo "$f" >$f || return 1
		done &&
		git add . &&
		git commit -m init &&
		git config index.sparse true &&
		git sparse-checkout set in/deeper &&

		git ls-files --sparse >files &&
		test_grep "^out/$" files &&
		test_grep "^in/other/$" files &&
		test_grep "^in/a$" files &&

		write_script .git/hooks/virtualfilesystem <<-\EOF &&
		tr "\n" "\0" <.git/vfs-paths
		EOF
		git config core.virtualfilesystem .git/hooks/virtualfilesystem
	)
'

test_expect_success 'paths inside sparse directories do not expand the index' '
	cat >repo/.git/vfs-paths <<-\EOF &&
	r
	in/a
	in/deeper/a
	in/other/a
	out/f1
	out/sub/f
	out/sub/
	EOF
	rm -f trace.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace.txt" \
		git -C repo -c core.ignorecase=false \
		ls-files -t --sparse >actual &&
	test_no_index_expansion trace.txt &&
	test_trace2_data vfs apply/nr_unknown 3 <trace.txt &&

	cat >expect <<-\EOF &&
	H in/a
	H in/deeper/a
	S in/other/
	S out/
	H r
	EOF
	test_cmp expect actual
'

test_expect_success 'directory wildcard keeps nested sparse directory' '
	cat >repo/.git/vfs-paths <<-\EOF &&
	in/
	EOF
	rm -f trace.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace.txt" \
		git -C repo ls-files -t --sparse >actual &&
	test_no_index_expansion trace.txt &&

	cat >expect <<-\EOF &&
	H in/a
	H in/deeper/a
	S in/other/
	S out/
	S r
	EOF
	test_cmp expect actual
'

test_expect_success 'case-insensitive lookups still match in-cone paths' '
	cat >repo/.git/vfs-paths <<-\EOF &&
	IN/A
	OUT/f1
	In/Other/
	EOF
	rm -f trace.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace.txt" \
		git -C repo -c core.ignorecase=true \
		ls-files -t --sparse >actual &&
	test_no_index_expansion trace.txt &&

	cat >expect <<-\EOF &&
	H in/a
	S in/deeper/a
	S in/other/
	S out/
	S r
	EOF
	test_cmp expect actual
'

test_expect_success 'status reports in-cone changes without expanding' '
	test_when_finished "git -C repo checkout -- in/a" &&
	cat >repo/.git/vfs-paths <<-\EOF &&
	r
	in/a
	in/deeper/a
	out/f1
	EOF
	echo changed >>repo/in/a &&
	rm -f trace.txt &&
	GIT_TRACE2_EVENT="$(pwd)/trace.txt" \
		git -C repo status --porcelain --untracked-files=no >actual &&
	test_no_index_expansion trace.txt &&
	echo " M in/a" >expect &&
	test_cmp expect actual &&

	git -C repo ls-files --sparse >files &&
	test_grep "^out/$" files
'

test_expect_success 'full index keeps the original behavior' '
	git clone repo full &&
	(
		cd full &&
		git sparse-checkout set in/deeper &&
		git config index.sparse false &&
		git sparse-checkout reapply &&
		cp ../repo/.git/hooks/virtualfilesystem .git/hooks/ &&
		cat >.git/vfs-paths <<-\EOF &&
		r
		in/a
		in/deeper/a
		out/f1
		out/sub/
		EOF
		git config core.virtualfilesystem \
			.git/hooks/virtualfilesystem &&

		GIT_TRACE2_EVENT="$(pwd)/../full-trace.txt" \
			git ls-files -t >../full-actual
	) &&
	test_trace2_data vfs apply/nr_unknown 0 <full-trace.txt &&

	cat >expect <<-\EOF &&
	H in/a
	H in/deeper/a
	S in/other/a
	H out/f1
	S out/f2
	H out/sub/f
	H r
	EOF
	test_cmp expect full-actual
'

test_done
