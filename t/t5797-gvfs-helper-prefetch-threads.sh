#!/bin/sh

test_description='gvfs-helper prefetch with gvfs.prefetchThreads config

Verify that the prefetch verb works correctly in both sequential
(gvfs.prefetchThreads=1) and parallel (gvfs.prefetchThreads=4) modes.
Each test is run under both configurations to ensure identical results
and to exercise both code paths in install_prefetch().
'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

# Helper: run a prefetch that fetches all 3 epoch packs (no --since).
#
do_prefetch_all () {
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch >OUT.output 2>OUT.stderr &&

	verify_received_packfile_count 3 &&
	verify_prefetch_keeps 1200000000
}

# Helper: run a prefetch with --since to get 2 of 3 packs.
#
do_prefetch_since () {
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch --since="1000000000" >OUT.output 2>OUT.stderr &&

	verify_received_packfile_count 2 &&
	verify_prefetch_keeps 1200000000
}

# Helper: prefetch then re-prefetch to verify up-to-date handling.
#
do_prefetch_up_to_date () {
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch --since="1000000000" >OUT.output 2>OUT.stderr &&

	verify_received_packfile_count 2 &&
	verify_prefetch_keeps 1200000000 &&

	# Re-fetch; should find nothing new.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch >OUT.output 2>OUT.stderr &&

	verify_received_packfile_count 0 &&
	verify_prefetch_keeps 1200000000
}

# Helper: prefetch corrupt pack (error path).
# Requires the server to be started with the appropriate mayhem.
#
do_prefetch_corrupt_pack () {
	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
			--cache-server=disable \
			--remote=origin \
			--no-progress \
			prefetch \
			--max-retries=0 \
			--since="1000000000" \
			>OUT.output 2>OUT.stderr &&

	test_grep "error: .* index-pack failed" OUT.stderr
}

for threads in 1 4
do
	# Describe the mode for readable test names.
	if test "$threads" = "1"
	then
		mode="sequential"
		# The sequential path logs install_mode=1.
		expected_mode=1
	else
		mode="parallel"
		expected_mode=$threads
	fi

	test_expect_success "prefetch all packs ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		git -C "$REPO_T1" config gvfs.prefetchThreads '$threads' &&

		GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
		export GIT_TRACE2_EVENT &&

		do_prefetch_all &&

		stop_gvfs_protocol_server &&

		test_trace2_data gvfs-helper prefetch/install_mode '$expected_mode' \
			<"trace-$test_count.txt"
	'

	test_expect_success "prefetch with --since ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		git -C "$REPO_T1" config gvfs.prefetchThreads '$threads' &&

		GIT_TRACE2_EVENT="$(pwd)/trace-$test_count.txt" &&
		export GIT_TRACE2_EVENT &&

		do_prefetch_since &&

		stop_gvfs_protocol_server &&

		test_trace2_data gvfs-helper prefetch/install_mode '$expected_mode' \
			<"trace-$test_count.txt"
	'

	test_expect_success "prefetch up-to-date ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server &&
		git -C "$REPO_T1" config gvfs.prefetchThreads '$threads' &&

		do_prefetch_up_to_date &&

		stop_gvfs_protocol_server
	'

	test_expect_success "prefetch corrupt pack ($mode, threads=$threads)" '
		test_when_finished "per_test_cleanup" &&
		start_gvfs_protocol_server_with_mayhem \
			bad_prefetch_pack_sha \
			no_prefetch_idx &&
		git -C "$REPO_T1" config gvfs.prefetchThreads '$threads' &&

		do_prefetch_corrupt_pack &&

		stop_gvfs_protocol_server
	'
done

test_done
