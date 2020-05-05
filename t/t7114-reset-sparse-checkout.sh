#!/bin/sh

test_description='reset when using a sparse-checkout'

. ./test-lib.sh

# reset using a sparse-checkout file

test_expect_success 'setup' '
	test_tick &&
	echo "checkout file" >c &&
	echo "modify file" >m &&
	echo "delete file" >d &&
	git add . &&
	git commit -m "initial commit" &&
	echo "added file" >a &&
	echo "modification of a file" >m &&
	git rm d &&
	git add . &&
	git commit -m "second commit" &&
	git checkout -b endCommit
'

test_expect_success 'reset when there is a sparse-checkout' '
	echo "/c" >.git/info/sparse-checkout &&
	test_config core.sparsecheckout true &&
	git checkout -B resetBranch &&
	test_path_is_missing m &&
	test_path_is_missing a &&
	test_path_is_missing d &&
	git reset HEAD~1 &&
	test "checkout file" = "$(cat c)" &&
	test "modification of a file" = "$(cat m)" &&
	test "added file" = "$(cat a)" &&
	test_path_is_missing d
'

test_expect_success 'reset after deleting file without skip-worktree bit' '
	git checkout -f endCommit &&
	git clean -xdf &&
	echo "/c
/m" >.git/info/sparse-checkout &&
	test_config core.sparsecheckout true &&
	git checkout -B resetAfterDelete &&
	test_path_is_file m &&
	test_path_is_missing a &&
	test_path_is_missing d &&
	rm -f m &&
	git reset HEAD~1 &&
	test "checkout file" = "$(cat c)" &&
	test "added file" = "$(cat a)" &&
	test_path_is_missing m &&
	test_path_is_missing d
'



test_done
