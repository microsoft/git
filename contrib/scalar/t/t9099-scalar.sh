#!/bin/sh

test_description='test the `scalar` command'

TEST_DIRECTORY=$(pwd)/../../../t
export TEST_DIRECTORY

# Make it work with --no-bin-wrappers
PATH=$(pwd)/..:$PATH

. ../../../t/test-lib.sh

GIT_TEST_MAINT_SCHEDULER="crontab:test-tool crontab ../cron.txt"
export GIT_TEST_MAINT_SCHEDULER

# Do not write any files outside the trash directory
Scalar_UNATTENDED=1
export Scalar_UNATTENDED

test_expect_success 'scalar shows a usage' '
	test_expect_code 129 scalar -h
'

test_expect_success 'set up repository to clone' '
	test_commit first &&
	test_commit second &&
	test_commit third &&
	git switch -c parallel first &&
	mkdir -p 1/2 &&
	test_commit 1/2/3 &&
	git config uploadPack.allowFilter true &&
	git config uploadPack.allowAnySHA1InWant true
'

test_expect_success 'scalar clone' '
	second=$(git rev-parse --verify second:second.t) &&
	scalar clone "file://$(pwd)" cloned --single-branch &&
	(
		cd cloned/src &&

		git config --get --global --fixed-value maintenance.repo \
			"$(pwd)" &&

		git for-each-ref --format="%(refname)" refs/remotes/origin/ >actual &&
		echo "refs/remotes/origin/parallel" >expect &&
		test_cmp expect actual &&

		test_path_is_missing 1/2 &&
		test_must_fail git rev-list --missing=print $second &&
		git rev-list $second &&
		git cat-file blob $second >actual &&
		echo "second" >expect &&
		test_cmp expect actual
	)
'

SQ="'"
test_expect_success UNZIP 'scalar diagnose' '
	(
		cd cloned/src &&
		scalar diagnose >out &&
		cat out &&
		sed -n "s/.*$SQ\\(.*\\.zip\\)$SQ.*/\\1/p" <out >zip_path &&
		zip_path=$(cat zip_path) &&
		test -n "$zip_path" &&
		unzip -v "$zip_path" &&
		folder=${zip_path%.zip} &&
		test_path_is_missing "$folder" &&
		unzip -p "$zip_path" diagnostics.log >out &&
		test_file_not_empty out
	)
'

GIT_TEST_ALLOW_GVFS_VIA_HTTP=1
export GIT_TEST_ALLOW_GVFS_VIA_HTTP

test_set_port GIT_TEST_GVFS_PROTOCOL_PORT
HOST_PORT=127.0.0.1:$GIT_TEST_GVFS_PROTOCOL_PORT
PID_FILE="$(pwd)"/pid-file.pid
SERVER_LOG="$(pwd)"/OUT.server.log

test_atexit '
	test -f "$PID_FILE" || return 0

	# The server will shutdown automatically when we delete the pid-file.
	rm -f "$PID_FILE"

	test -z "$verbose$verbose_log" || {
		echo "server log:"
		cat "$SERVER_LOG"
	}

	# Give it a few seconds to shutdown (mainly to completely release the
	# port before the next test start another instance and it attempts to
	# bind to it).
	for k in $(test_seq 5)
	do
		grep -q "Starting graceful shutdown" "$SERVER_LOG" &&
		return 0 ||
		sleep 1
	done

	echo "stop_gvfs_protocol_server: timeout waiting for server shutdown"
	return 1
'

start_gvfs_enabled_http_server () {
	GIT_HTTP_EXPORT_ALL=1 \
	test-gvfs-protocol --verbose \
		--listen=127.0.0.1 \
		--port=$GIT_TEST_GVFS_PROTOCOL_PORT \
		--reuseaddr \
		--pid-file="$PID_FILE" \
		2>"$SERVER_LOG" &

	for k in 0 1 2 3 4
	do
		if test -f "$PID_FILE"
		then
			return 0
		fi
		sleep 1
	done
	return 1
}

test_expect_success 'start GVFS-enabled server' '
	git config uploadPack.allowFilter false &&
	git config uploadPack.allowAnySHA1InWant false &&
	start_gvfs_enabled_http_server
'

test_expect_success '`scalar clone` with GVFS-enabled server' '
	: the fake cache server requires fake authentication &&
	git config --global core.askPass true &&
	scalar clone --single-branch -- http://$HOST_PORT/ using-gvfs &&

	: verify that the shared cache has been configured &&
	cache_key="url_$(printf "%s" http://$HOST_PORT/ |
		tr A-Z a-z |
		test-tool sha1)" &&
	echo "$(pwd)/using-gvfs/.scalarCache/$cache_key" >expect &&
	git -C using-gvfs/src config gvfs.sharedCache >actual &&
	test_cmp expect actual &&

	second=$(git rev-parse --verify second:second.t) &&
	(
		cd using-gvfs/src &&
		test_path_is_missing 1/2 &&
		GIT_TRACE=$PWD/trace.txt git cat-file blob $second >actual &&
		: verify that the gvfs-helper was invoked to fetch it &&
		test_i18ngrep gvfs-helper trace.txt &&
		echo "second" >expect &&
		test_cmp expect actual
	)
'

test_done
