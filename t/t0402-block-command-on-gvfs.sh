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
not_with_gvfs repack
not_with_gvfs submodule status
not_with_gvfs update-index --index-version 2
not_with_gvfs update-index --skip-worktree
not_with_gvfs update-index --no-skip-worktree
not_with_gvfs update-index --split-index
not_with_gvfs worktree list

test_expect_success 'test gc --auto succeeds when disabled via config' '
	test_config core.gvfs true &&
	test_config gc.auto 0 &&
	git gc --auto
'

test_expect_success 'update-git-for-windows disabled' '
	test_must_fail git update 2>out &&
	test_i18ngrep VFS out &&
	test_must_fail git update-git-for-windows 2>out &&
	test_i18ngrep VFS out
'

test_done
