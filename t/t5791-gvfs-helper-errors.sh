#!/bin/sh

test_description='gvfs-helper error handling tests'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

#################################################################
# Tests to see how gvfs-helper responds to network problems.
#
# We use small --max-retry value because of exponential backoff.
#
# These mayhem tests are interested in how gvfs-helper gracefully
# retries when there is a network error.  And verify that it gives
# up gracefully too.
#################################################################

mayhem_observed__close__connections () {
	if grep "transient" OUT.stderr
	then
		# Transient errors should retry.
		# 1 for initial request + 2 retries.
		#
		verify_connection_count 3
		return $?
	elif grep "hard_fail" OUT.stderr
	then
		# Hard errors should not retry.
		#
		verify_connection_count 1
		return $?
	else
		error "mayhem_observed__close: unexpected mayhem-induced error type"
		return 1
	fi
}

mayhem_observed__close () {
	# Expected error codes for mayhem events:
	#     close_read
	#     close_write
	#     close_no_write
	#
	# CURLE_PARTIAL_FILE 18
	# CURLE_GOT_NOTHING 52
	# CURLE_SEND_ERROR 55
	# CURLE_RECV_ERROR 56
	#
	# I don't want to pin it down to an exact error for each because there may
	# be races here because of network buffering.
	#
	# Also, It is unclear which of these network errors should be transient
	# (with retry) and which should be a hard-fail (without retry).  I'm only
	# going to verify the connection counts based upon what type of error
	# gvfs-helper claimed it to be.
	#
	if      grep "error: get: (curl:18)" OUT.stderr ||
		grep "error: get: (curl:52)" OUT.stderr ||
		grep "error: get: (curl:55)" OUT.stderr ||
		grep "error: get: (curl:56)" OUT.stderr
	then
		mayhem_observed__close__connections
		return $?
	else
		echo "mayhem_observed__close: unexpected mayhem-induced error"
		return 1
	fi
}

test_lazy_prereq CURL_8_16_0 '
	git gvfs-helper curl-version = 8.16.0 ||
	test 8.15.0-DEV = "$(git gvfs-helper curl-version)"
'

test_expect_success 'curl-error: no server' '
	test_when_finished "per_test_cleanup" &&

	connect_timeout_ms= &&
	# CURLE_COULDNT_CONNECT 7
	regex="error: get: (curl:7)" &&
	if test_have_prereq CURL_8_16_0
	then
		connect_timeout_ms=--connect-timeout-ms=200 &&
		# CURLE_COULDNT_CONNECT 7
		# CURLE_OPERATION_TIMEDOUT 28
		regex="error: get: (curl:\(7\|28\))"
	fi &&

	# Try to do a multi-get without a server.
	#
	# Use small max-retry value because of exponential backoff,
	# but yet do exercise retry some.
	#
	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		$connect_timeout_ms \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&
	test_grep "$regex" OUT.stderr
'

test_expect_success 'curl-error: close socket while reading request' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem close_read &&

	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	mayhem_observed__close
'

test_expect_success 'curl-error: close socket while writing response' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem close_write &&

	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	mayhem_observed__close
'

test_expect_success 'curl-error: close socket before writing response' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem close_no_write &&

	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	mayhem_observed__close
'

#################################################################
# Tests to confirm that gvfs-helper does silently recover when
# a retry succeeds.
#
# Note: I'm only to do this for 1 of the close_* mayhem events.
#################################################################

test_expect_success 'successful retry after curl-error: origin get' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem close_read_1 &&

	# Connect to the origin server (w/o auth).
	# Make a single-object GET request.
	# Confirm that it succeeds without error.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OID_ONE_BLOB_FILE" >OUT.output &&

	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "loose <oid>" message for each received object.
	# Verify that gvfs-helper received each of the requested objects.
	#
	sed "s/loose //" <OUT.output | sort >OUT.actual &&
	test_cmp "$OID_ONE_BLOB_FILE" OUT.actual &&

	verify_objects_in_shared_cache "$OID_ONE_BLOB_FILE" &&
	verify_connection_count 2
'

#################################################################
# Tests to see how gvfs-helper responds to HTTP errors/problems.
#
#################################################################

# See "enum gh__error_code" in gvfs-helper.c
#
GH__ERROR_CODE__HTTP_404=4
GH__ERROR_CODE__HTTP_429=5
GH__ERROR_CODE__HTTP_503=6

test_expect_success 'http-error: 503 Service Unavailable (with retry)' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_503 &&

	test_expect_code $GH__ERROR_CODE__HTTP_503 \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	test_grep "error: get: (http:503)" OUT.stderr &&
	verify_connection_count 3
'

test_expect_success 'http-error: 429 Service Unavailable (with retry)' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_429 &&

	test_expect_code $GH__ERROR_CODE__HTTP_429 \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	test_grep "error: get: (http:429)" OUT.stderr &&
	verify_connection_count 3
'

test_expect_success 'http-error: 404 Not Found (no retry)' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_404 &&

	test_expect_code $GH__ERROR_CODE__HTTP_404 \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OID_ONE_BLOB_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	test_grep "error: get: (http:404)" OUT.stderr &&
	verify_connection_count 1
'

#################################################################
# Tests to confirm that gvfs-helper does silently recover when an
# HTTP request succeeds after a failure.
#
#################################################################

test_expect_success 'successful retry after http-error: origin get' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_429_1 &&

	# Connect to the origin server (w/o auth).
	# Make a single-object GET request.
	# Confirm that it succeeds without error.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		--max-retries=2 \
		<"$OID_ONE_BLOB_FILE" >OUT.output &&

	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "loose <oid>" message for each received object.
	# Verify that gvfs-helper received each of the requested objects.
	#
	sed "s/loose //" <OUT.output | sort >OUT.actual &&
	test_cmp "$OID_ONE_BLOB_FILE" OUT.actual &&

	verify_objects_in_shared_cache "$OID_ONE_BLOB_FILE" &&
	verify_connection_count 2
'

#################################################################
# So far we have confirmed that gvfs-helper can recover from a network
# error (with retries, since the cache-server was disabled in all of
# the above tests).  Try again with fallback turned on.
#
# With mayhem "http_503" turned on both the cache and origin server
# will always throw a 503 error.
#
# Confirm that we tried to make six connections: we should hit the
# cache-server 3 times (one initial attempt and two retries) and then
# try the origin server 3 times.
#
#################################################################

test_expect_success 'http-error: 503 Service Unavailable (with retry and fallback)' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_503 &&

	test_expect_code $GH__ERROR_CODE__HTTP_503 \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--fallback \
		get \
		--max-retries=2 \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	test_grep "error: get: (http:503)" OUT.stderr &&
	verify_connection_count 6
'

#################################################################
# Now repeat the above, but explicitly turn off fallback.
#
# Again, we use mayhem "http_503".  However, with fallback turned
# off, we will only attempt the 3 connections to the cache server.
# We will not try to hit the origin server.
#
# So we should only see a total of 3 connections rather than the
# six in the previous test.
#
#################################################################

test_expect_success 'http-error: 503 Service Unavailable (with retry and no-fallback)' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_503 &&

	test_expect_code $GH__ERROR_CODE__HTTP_503 \
		git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--no-fallback \
		get \
		--max-retries=2 \
		<"$OIDS_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	test_grep "error: get: (http:503)" OUT.stderr &&
	verify_connection_count 3
'

test_done
