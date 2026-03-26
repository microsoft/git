#!/bin/sh

test_description='block commands in GVFS repo'

. ./test-lib.sh

not_with_gvfs () {
	command=$1 &&
	shift &&
	test_expect_success "test $command $*" "
		test_config alias.g4rbled $command &&
		test_config core.gvfs true &&
		test_must_fail git $command $* &&
		test_must_fail git g4rbled $* &&
		test_unconfig core.gvfs &&
		test_must_fail git -c core.gvfs=true $command $* &&
		test_must_fail git -c core.gvfs=true g4rbled $*
	"
}

not_with_gvfs fsck
not_with_gvfs gc
not_with_gvfs gc --auto
not_with_gvfs prune
not_with_gvfs submodule status
not_with_gvfs update-index --index-version 2
not_with_gvfs update-index --skip-worktree
not_with_gvfs update-index --no-skip-worktree
not_with_gvfs update-index --split-index

# worktree is conditionally allowed: blocked when VFS enabled without
# GVFS_SUPPORTS_WORKTREES.
test_expect_success 'worktree blocked with VFS but without SUPPORTS_WORKTREES' '
	test_config core.gvfs $((0xffff & ~(1<<8))) && # all bits except GVFS_SUPPORTS_WORKTREES
	test_must_fail git worktree list 2>err &&
	test_grep "not supported when using the virtual file system" err
'

test_expect_success 'worktree operations work when SUPPORTS_WORKTREES is set' '
	test_commit initial &&

	# Use core.gvfs=true which sets all bits including SUPPORTS_WORKTREES.
	test_config core.gvfs true &&

	# add: succeeds, forces --no-checkout (no initial.t on disk)
	git worktree add ../vfs-wt &&
	test_path_exists ../vfs-wt/.git &&
	! test_path_exists ../vfs-wt/initial.t &&

	# list: shows the worktree
	git worktree list >out &&
	grep "vfs-wt" out &&

	# remove: cleans up
	git worktree remove --force ../vfs-wt &&
	! test_path_exists ../vfs-wt
'

test_expect_success 'test gc --auto succeeds when disabled via config' '
	test_config core.gvfs true &&
	test_config gc.auto 0 &&
	git gc --auto
'

test_expect_success 'test repack fails with VFS bit enabled' '
	test_config core.gvfs true &&
	test_must_fail git repack
'

test_expect_success 'test repack succeeds with VFS bit disabled' '
	test_config core.gvfs 150 &&
	git repack
'

test_done
