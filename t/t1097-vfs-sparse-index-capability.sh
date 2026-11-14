#!/bin/sh

test_description='git version advertises the vfs-sparse-index capability

"git version --build-options" prints "feature: vfs-sparse-index", and
"git version" without the option does not. The line tells a virtual file
system that this build supports a sparse index under
core.virtualFilesystem. t1094, t1095, and t1096 test that behavior.'

. ./test-lib.sh

test_expect_success 'git version --build-options prints the capability' '
	git version --build-options >out &&
	test_grep "^feature: vfs-sparse-index$" out
'

test_expect_success 'git --version --build-options prints the capability' '
	git --version --build-options >out &&
	test_grep "^feature: vfs-sparse-index$" out
'

test_expect_success 'git version without --build-options omits the capability' '
	git version >out &&
	test_grep ! "^feature: vfs-sparse-index$" out
'

test_done
