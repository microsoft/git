#!/bin/sh

test_description='internal file system watcher'

. ./test-lib.sh

git fsmonitor--daemon --is-supported || {
	skip_all="The internal FSMonitor is not supported on this platform"
	test_done
}

test_expect_success 'can start and stop the daemon' '
	test_when_finished \
		"test_might_fail git -C test fsmonitor--daemon --stop" &&
	git init test &&
	(
		cd test &&
		: start the daemon implicitly by querying it &&
		GIT_TRACE2_EVENT="$PWD/../.git/trace" \
		git fsmonitor--daemon --query 1 0 >actual &&
		grep "fsmonitor.*serve" ../.git/trace &&
		git config dummy.value 1 &&
		sleep 0 &&
		! grep "fsmonitor.*git/config" ../.git/trace &&
		git fsmonitor--daemon --is-running &&
		nul_to_q <actual >actual.filtered &&
		grep "^[1-9][0-9]*Q/Q$" actual.filtered
	) &&
	sleep 0 &&
	rm -rf test/.git &&
	test_must_fail git -C test fsmonitor--daemon --is-running
'

test_expect_success 'setup' '
	>tracked &&
	>modified &&
	mkdir dir1 &&
	>dir1/tracked &&
	>dir1/modified &&
	mkdir dir2 &&
	>dir2/tracked &&
	>dir2/modified &&
	git -c core.fsmonitor= add . &&
	test_tick &&
	git -c core.fsmonitor= commit -m initial &&
	git config core.fsmonitor :internal: &&
	git update-index --fsmonitor &&
	cat >.gitignore <<-\EOF &&
	.gitignore
	expect*
	actual*
	EOF
	>.git/trace &&
	echo 1 >modified &&
	echo 2 >dir1/modified &&
	echo 3 >dir2/modified &&
	>dir1/untracked &&
	git fsmonitor--daemon --stop &&
	test_must_fail git fsmonitor--daemon --is-running
'

test_expect_success 'internal fsmonitor works' '
	GIT_INDEX=.git/fresh-index git read-tree master &&
	GIT_INDEX=.git/fresh-index git -c core.fsmonitor= status >expect &&
	GIT_TRACE2_EVENT="$PWD/.git/trace" git status >actual &&
	test_cmp expect actual &&
	! grep yep .git/trace &&
	>yep &&
	grep yep .git/trace
'

test_expect_success 'can stop internal fsmonitor' '
	if git fsmonitor--daemon --is-running
	then
		git fsmonitor--daemon --stop
	fi &&
	test_must_fail git fsmonitor--daemon --is-running
'

test_done
