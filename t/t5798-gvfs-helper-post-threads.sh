#!/bin/sh

test_description='gvfs-helper POST with gvfs.postThreads config

Verify that the post verb works correctly in both sequential
(gvfs.postThreads=1) and parallel (gvfs.postThreads=4) modes.
Each test is run under both configurations to ensure identical results
and to exercise both code paths in do__http_post__fetch_oidset().
'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

test_lazy_prereq TIMEOUT '
	type timeout >/dev/null 2>&1
'

# Helper: POST a set of OIDs and verify we get the expected packfiles.
#
do_post_blobs () {
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_received_packfile_count 1 &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE"
}

# Helper: POST blobs with a small block size to force multiple batches.
#
do_post_blobs_small_blocks () {
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		--block-size=2 \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE"
}

# Helper: leave one OID after the first nominal block. The parallel
# partitioner must avoid sending that object as a loose-object response to
# index-pack.
#
do_post_blobs_single_oid_remainder () {
	nr_oids=$(sort -u "$OIDS_BLOBS_FILE" | wc -l) &&
	block_size=$(($nr_oids - 1)) &&

	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		--block-size="$block_size" \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE"
}

# Helper: POST same set twice to test duplicate handling.
#
do_post_duplicate () {
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_received_packfile_count 1 &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE" &&

	# Second fetch of same objects should still succeed.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE"
}

verify_parallel_post_workers () {
	trace_file=$1 &&

	test_trace2_data gvfs-helper post/fetch_mode 4 <"$trace_file" &&
	nr_workers=$(grep "\"key\":\"post/worker\"" "$trace_file" |
		sed -n "s/.*\"value\":\"\\([0-9]*\\)\".*/\\1/p" |
		sort -u | wc -l) &&
	test "$nr_workers" -gt 1
}

do_post_corrupt_pack () {
	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
			--cache-server=disable \
			--remote=origin \
			--no-progress \
			post \
			--block-size=2 \
			--max-retries=0 \
			<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_grep "error: post: index-pack failed" OUT.stderr
}

for value in unset 0 negative
do
	test_expect_success "postThreads=$value uses sequential mode" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		if test "'$value'" = unset
		then
			git -C "$REPO_T1" config --unset-all \
				gvfs.postThreads || :
		elif test "'$value'" = negative
		then
			git -C "$REPO_T1" config gvfs.postThreads -1
		else
			git -C "$REPO_T1" config gvfs.postThreads 0
		fi &&

		GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
		export GIT_TRACE2_EVENT &&

		do_post_blobs_small_blocks &&

		stop_gvfs_protocol_server &&
		test_trace2_data gvfs-helper post/fetch_mode 1 \
			<"trace-$test_count.txt"
	'
done

test_expect_success 'malformed postThreads is rejected' '
	test_when_finished "git -C \"$REPO_T1\" config --unset-all \
		gvfs.postThreads" &&
	git -C "$REPO_T1" config gvfs.postThreads invalid &&

	test_must_fail git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&
	test_grep "bad numeric config value" OUT.stderr
'

test_expect_success PTHREADS 'cookie configuration uses sequential POST' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "rm -f cookies" &&
	>"cookies" &&
	start_gvfs_protocol_server &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	git -C "$REPO_T1" \
		-c http.cookieFile="$(pwd)/cookies" \
		-c http.saveCookies=true \
		gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		--block-size=2 \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE" &&
	stop_gvfs_protocol_server &&
	test_trace2_data gvfs-helper post/fetch_mode 1 \
		<"trace-$test_count.txt"
'

for threads in 1 4
do
	if test "$threads" = "1"
	then
		mode="sequential"
		prereq=
		expected_mode=1
	else
		mode="parallel"
		prereq=PTHREADS
		expected_mode=$threads
	fi

	test_expect_success "$prereq" \
		"post blobs ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		git -C "$REPO_T1" config gvfs.postThreads '$threads' &&

		GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
		export GIT_TRACE2_EVENT &&

		do_post_blobs &&

		stop_gvfs_protocol_server &&

		test_trace2_data gvfs-helper post/fetch_mode '$expected_mode' \
			<"trace-$test_count.txt"
	'

	test_expect_success "$prereq" \
		"post small blocks ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		git -C "$REPO_T1" config gvfs.postThreads '$threads' &&

		GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
		export GIT_TRACE2_EVENT &&

		do_post_blobs_small_blocks &&

		stop_gvfs_protocol_server &&

		if test '$threads' = 4
		then
			verify_parallel_post_workers \
				"trace-$test_count.txt"
		else
			test_trace2_data gvfs-helper post/fetch_mode 1 \
				<"trace-$test_count.txt"
		fi
	'

	test_expect_success "$prereq" \
		"post single-OID remainder ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		git -C "$REPO_T1" config gvfs.postThreads '$threads' &&

		GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
		export GIT_TRACE2_EVENT &&

		do_post_blobs_single_oid_remainder &&

		stop_gvfs_protocol_server &&

		test_trace2_data gvfs-helper post/fetch_mode '$expected_mode' \
			<"trace-$test_count.txt"
	'

	test_expect_success "$prereq" \
		"post duplicate ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		git -C "$REPO_T1" config gvfs.postThreads '$threads' &&

		GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
		export GIT_TRACE2_EVENT &&

		do_post_duplicate &&

		stop_gvfs_protocol_server &&

		test_trace2_data gvfs-helper post/fetch_mode '$expected_mode' \
			<"trace-$test_count.txt"
	'
done

test_expect_success PTHREADS,TIMEOUT 'parallel POST does not deadlock' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	timeout 30 git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		--block-size=2 \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE" &&
	stop_gvfs_protocol_server &&
	test_trace2_data gvfs-helper post/fetch_mode 4 \
		<"trace-$test_count.txt"
'

test_expect_success PTHREADS 'parallel POST reports index-pack failure' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem bad_post_pack_sha &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	do_post_corrupt_pack &&

	stop_gvfs_protocol_server &&
	test_grep "bad_post_pack_sha" "$SERVER_LOG" &&
	test_trace2_data gvfs-helper post/fetch_mode 4 \
		<"trace-$test_count.txt"
'

test_expect_success PTHREADS 'parallel POST retries a corrupt pack' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem bad_post_pack_sha_1 &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	do_post_blobs_small_blocks &&

	stop_gvfs_protocol_server &&
	test_grep "bad_post_pack_sha_1" "$SERVER_LOG" &&
	test_trace2_data gvfs-helper post/fetch_mode 4 \
		<"trace-$test_count.txt"
'

test_expect_success PTHREADS 'parallel POST retries a transient HTTP error' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_429_1 &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	do_post_blobs_small_blocks &&

	stop_gvfs_protocol_server &&
	test_grep "http_429_1" "$SERVER_LOG" &&
	test_trace2_data gvfs-helper post/fetch_mode 4 \
		<"trace-$test_count.txt"
'

test_expect_success PTHREADS 'parallel POST retries authentication' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_401_1 &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	do_post_blobs_small_blocks &&

	stop_gvfs_protocol_server &&
	test_grep "http_401_1" "$SERVER_LOG" &&
	test_trace2_data gvfs-helper post/fetch_mode 4 \
		<"trace-$test_count.txt" &&
	test_trace2_data gvfs-helper post/auth_retry 1 \
		<"trace-$test_count.txt"
'

test_expect_success PTHREADS 'parallel POST falls back after cache 404' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem cache_http_404 &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--fallback \
		--no-progress \
		post \
		--block-size=2 \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE" &&
	stop_gvfs_protocol_server &&
	test_grep "cache_http_404" "$SERVER_LOG" &&
	test_trace2_data gvfs-helper post/fetch_mode 4 \
		<"trace-$test_count.txt"
'

test_expect_success PTHREADS 'parallel POST honors --no-fallback' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem cache_http_404 &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
			--cache-server=trust \
			--remote=origin \
			--no-fallback \
			--no-progress \
			post \
			--block-size=2 \
			<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_grep "error: post: (http:404)" OUT.stderr &&
	stop_gvfs_protocol_server &&
	test_grep "cache_http_404" "$SERVER_LOG" &&
	test_trace2_data gvfs-helper post/fetch_mode 4 \
		<"trace-$test_count.txt"
'

test_expect_success PTHREADS 'parallel POST preserves configured headers' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&
	git -C "$REPO_T1" config gvfs.postThreads 4 &&

	GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
	export GIT_TRACE2_EVENT &&

	git -C "$REPO_T1" \
		-c http.extraHeader="X-Test-Header: parallel" \
		-c gvfs.sessionkey=test.id \
		-c test.id=parallel-session \
		gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		--block-size=2 \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	test_must_be_empty OUT.stderr &&
	stop_gvfs_protocol_server &&
	test_grep "X-Test-Header: parallel" "$SERVER_LOG" &&
	test_grep "X-Session-Id:.*parallel-session:.*-P" "$SERVER_LOG" &&
	verify_parallel_post_workers "trace-$test_count.txt"
'

test_done
