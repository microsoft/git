#!/bin/sh

test_description='gvfs-helper integration tests with Git commands'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

#################################################################
# Integration tests with Git.exe
#
# Now that we have confirmed that gvfs-helper works in isolation,
# run a series of tests using random Git commands that fault-in
# objects as needed.
#
# At this point, I'm going to stop verifying the shape of the ODB
# (loose vs packfiles) and the number of connections required to
# get them.  The tests from here on are to verify that objects are
# magically fetched whenever required.
#################################################################

test_expect_success 'integration: explicit commit/trees, implicit blobs: diff 2 commits' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# We have a very empty repo.  Seed it with all of the commits
	# and trees.  The purpose of this test is to demand-load the
	# needed blobs only, so we prefetch the commits and trees.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		<"$OIDS_CT_FILE" >OUT.output &&

	# Confirm that we do not have the blobs locally.
	# With gvfs-helper turned off, we should fail.
	#
	test_must_fail \
		git -C "$REPO_T1" -c core.useGVFSHelper=false \
			diff $(cat m1.branch)..$(cat m3.branch) \
			>OUT.output 2>OUT.stderr &&

	# Turn on gvfs-helper and retry.  This should implicitly fetch
	# any needed blobs.
	#
	git -C "$REPO_T1" -c core.useGVFSHelper=true \
		diff $(cat m1.branch)..$(cat m3.branch) \
		>OUT.output 2>OUT.stderr &&

	# Verify that gvfs-helper wrote the fetched the blobs to the
	# local ODB, such that a second attempt with gvfs-helper
	# turned off should succeed.
	#
	git -C "$REPO_T1" -c core.useGVFSHelper=false \
		diff $(cat m1.branch)..$(cat m3.branch) \
		>OUT.output 2>OUT.stderr
'

trace_has_queue_oid () {
	oid=$1
	grep "gh_client__queue_oid: $oid"
}

trace_has_immediate_oid () {
	oid=$1
	grep "gh_client__get_immediate: $oid"
}

test_expect_success 'integration: fully implicit: diff 2 commits' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Implicitly demand-load everything without any pre-seeding.
	#
	GIT_TRACE2_EVENT="$(pwd)/diff-trace.txt" \
	git -C "$REPO_T1" -c core.useGVFSHelper=true \
		diff $(cat m1.branch)..$(cat m3.branch) \
		>OUT.output 2>OUT.stderr &&

	oid=$(git -C "$REPO_SRC" rev-parse main:file9.txt.t) &&
	trace_has_queue_oid $oid <diff-trace.txt &&
	! trace_has_immediate_oid $oid <diff-trace.txt
'

# T1 should be considered contaminated at this point.

#################################################################
# gvfs-helper.exe defaults to no fallback.
# gvfs-helper-client.c defaults to adding `--fallback` to child process.
#
# `gvfs.fallback` was added to change the default behavior in the
# gvfs-helper-client.c code to add either `--fallback` or `--no-fallback`
# (for origin server load reasons).
#
# When `gvfs.fallback` is unset, we default to TRUE and pass `--fallback`.
# Otherwise, we use the boolean value to decide.
#
# NOTE: We DO NOT attempt to count connection requests in the
# following tests.  Since we are using a normal `git` command to drive
# the `gvfs-helper-client.c` code (and spawn `git-gvfs-helper.exe`) we
# cannot make assumptions on the number of child processes or
# reqeusts.  The "promisor" logic may drive one or more single-item
# GETs or a series of bulk POST attempts.  Therefore, we must rely
# only on the result of the command and (implicitly) whether all
# missing objects were resolved. We use mayhem features to selectively
# break the cache and origin servers.
#################################################################

test_expect_success 'integration: implicit-get: http_503: diff 2 commits' '
	test_when_finished "per_test_cleanup" &&

	# Tell both servers to always send 503.
	start_gvfs_protocol_server_with_mayhem http_503 &&

	# Implicitly demand-load everything without any pre-seeding.
	# (We cannot tell from whether fallback was used or not in this
	# limited test.)
	#
	test_must_fail \
		git -C "$REPO_T2" -c core.useGVFSHelper=true \
			diff $(cat m1.branch)..$(cat m3.branch) \
			>OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server
'

test_expect_success 'integration: implicit-get: cache_http_503,no-fallback: diff 2 commits' '
	test_when_finished "per_test_cleanup" &&

	# Tell cache server to send 503 and origin server to send 200.
	start_gvfs_protocol_server_with_mayhem cache_http_503 &&

	# Implicitly demand-load everything without any pre-seeding.
	# This should fail because we do not allow fallback.
	#
	test_must_fail \
		git -C "$REPO_T2" \
			-c core.useGVFSHelper=true \
			-c gvfs.fallback=false \
			diff $(cat m1.branch)..$(cat m3.branch) \
			>OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server
'

test_expect_success 'integration: implicit-get: cache_http_503,with-fallback: diff 2 commits' '
	test_when_finished "per_test_cleanup" &&

	# Tell cache server to send 503 and origin server to send 200.
	start_gvfs_protocol_server_with_mayhem cache_http_503 &&

	# Implicitly demand-load everything without any pre-seeding.
	#
	git -C "$REPO_T2" \
		-c core.useGVFSHelper=true \
		-c gvfs.fallback=true \
		diff $(cat m1.branch)..$(cat m3.branch) \
		>OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server
'

# T2 should be considered contaminated at this point.

test_done
