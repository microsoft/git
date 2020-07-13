#!/bin/sh

test_description='internal file system watcher'

. ./test-lib.sh

git fsmonitor--daemon --is-supported || {
	skip_all="The internal FSMonitor is not supported on this platform"
	test_done
}

# Tell the fsmonitor--daemon to stop, even if `--stop` failed
test_atexit '
	git fsmonitor--daemon --stop ||
	test -n "$debug" ||
	rm -r .git
'

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
	rm -rf test/.git &&
	test_must_fail git -C test fsmonitor--daemon --is-running
'

test_expect_success 'cannot start multiple daemons' '
	git fsmonitor--daemon --start &&

	#### HACK
	sleep 3 &&
	#### HACK

	git fsmonitor--daemon --is-running &&
	test_must_fail git fsmonitor--daemon --start &&
	git fsmonitor--daemon --stop &&

	#### HACK
	sleep 3 &&
	#### HACK

	test_must_fail git fsmonitor--daemon --is-running
'
# Note, after "git reset --hard HEAD" no extensions exist other than 'TREE'
# "git update-index --fsmonitor" can be used to get the extension written
# before testing the results.

clean_repo () {
	git reset --hard HEAD &&
	git clean -fd &&
	>.git/trace
}

test_expect_success 'setup' '
	>tracked &&
	>modified &&
	>delete &&
	>rename &&
	mkdir dir1 &&
	>dir1/tracked &&
	>dir1/modified &&
	>dir1/delete &&
	>dir1/rename &&
	mkdir dir2 &&
	>dir2/tracked &&
	>dir2/modified &&
	>dir2/delete &&
	>dir2/rename &&
	mkdir dirtorename &&
	>dirtorename/a &&
	>dirtorename/b &&
	git -c core.fsmonitor= add . &&
	test_tick &&
	git -c core.fsmonitor= commit -m initial &&
	git config core.fsmonitor :internal: &&
	GIT_TRACE2_EVENT="$PWD/.git/trace" git update-index --fsmonitor &&
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

edit_files() {
	echo 1 >modified
	echo 2 >dir1/modified
	echo 3 >dir2/modified
	>dir1/untracked
}

delete_files() {
	rm -f delete
	rm -f dir1/delete
	rm -f dir2/delete
}

create_files() {
	echo 1 >new
	echo 2 >dir1/new
	echo 3 >dir2/new
}

rename_files() {
	mv rename renamed
	mv dir1/rename dir1/renamed
	mv dir2/rename dir2/renamed
}

file_to_directory() {
	rm -f delete
	mkdir delete
	echo 1 >delete/new
}

directory_to_file() {
	rm -rf dir1
	echo 1 >dir1
}

verify_status() {
	GIT_TRACE2_EVENT="$PWD/.git/trace" git status >actual &&
	GIT_INDEX=.git/fresh-index git read-tree master &&
	GIT_INDEX=.git/fresh-index git -c core.fsmonitor= status >expect &&
	test_cmp expect actual
}

test_expect_success 'internal fsmonitor works' '
	verify_status &&
	git fsmonitor--daemon --is-running
'

test_expect_success 'edit some files' '
	clean_repo &&
	edit_files &&
	verify_status &&
	grep :\"dir1/modified\" .git/trace &&
	grep :\"dir2/modified\" .git/trace &&
	grep :\"modified\" .git/trace &&
	grep :\"dir1/untracked\" .git/trace
'

test_expect_success 'create some files' '
	clean_repo &&
	create_files &&
	verify_status &&
	grep :\"dir1/new\" .git/trace &&
	grep :\"dir2/new\" .git/trace &&
	grep :\"new\" .git/trace
'

test_expect_success 'delete some files' '
	clean_repo &&
	delete_files &&
	verify_status &&
	grep :\"dir1/delete\" .git/trace &&
	grep :\"dir2/delete\" .git/trace &&
	grep :\"delete\" .git/trace
'

test_expect_success 'rename some files' '
	clean_repo &&
	rename_files &&
	verify_status &&
	grep :\"dir1/rename\" .git/trace &&
	grep :\"dir2/rename\" .git/trace &&
	grep :\"rename\" .git/trace &&
	grep :\"dir1/renamed\" .git/trace &&
	grep :\"dir2/renamed\" .git/trace &&
	grep :\"renamed\" .git/trace
'

test_expect_success 'rename directory' '
	clean_repo &&
	mv dirtorename dirrenamed &&
	verify_status &&
	grep :\"dirtorename/*\" .git/trace &&
	grep :\"dirrenamed/*\" .git/trace
'


test_expect_success 'file changes to directory' '
	clean_repo &&
	file_to_directory &&
	verify_status &&
	grep :\"delete\" .git/trace &&
	grep :\"delete/new\" .git/trace
'

test_expect_success 'directory changes to a file' '
	clean_repo &&
	directory_to_file &&
	verify_status &&
	grep :\"dir1\" .git/trace
'

test_expect_success 'can stop internal fsmonitor' '
	if git fsmonitor--daemon --is-running
	then
		git fsmonitor--daemon --stop
	fi &&
	test_must_fail git fsmonitor--daemon --is-running
'

test_done
