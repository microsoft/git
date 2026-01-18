#!/bin/sh

test_description='test gvfs-helper and GVFS Protocol'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

#################################################################
# Basic tests to confirm the happy path works.
#################################################################

test_expect_success 'basic: GET origin multi-get no-auth' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Connect to the origin server (w/o auth) and make a series of
	# single-object GET requests.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		get \
		<"$OIDS_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "loose <oid>" message for each received object.
	# Verify that gvfs-helper received each of the requested objects.
	#
	sed "s/loose //" <OUT.output | sort >OUT.actual &&
	test_cmp "$OIDS_FILE" OUT.actual &&

	verify_objects_in_shared_cache "$OIDS_FILE" &&
	verify_connection_count 1
'

test_expect_success 'basic: GET cache-server multi-get trust-mode' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Connect to the cache-server and make a series of
	# single-object GET requests.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		get \
		<"$OIDS_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "loose <oid>" message for each received object.
	# Verify that gvfs-helper received each of the requested objects.
	#
	sed "s/loose //" <OUT.output | sort >OUT.actual &&
	test_cmp "$OIDS_FILE" OUT.actual &&

	verify_objects_in_shared_cache "$OIDS_FILE" &&
	verify_connection_count 1
'

test_expect_success 'basic: GET gvfs/config' '
#	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Connect to the cache-server and make a series of
	# single-object GET requests.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		config \
		<"$OIDS_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# The cache-server URL should be listed in the gvfs/config output.
	# We confirm this before assuming error-mode will work.
	#
	test_grep "$CACHE_URL" OUT.output
'

test_expect_success 'basic: GET cache-server multi-get error-mode' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Connect to the cache-server and make a series of
	# single-object GET requests.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=error \
		--remote=origin \
		get \
		<"$OIDS_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "loose <oid>" message for each received object.
	# Verify that gvfs-helper received each of the requested objects.
	#
	sed "s/loose //" <OUT.output | sort >OUT.actual &&
	test_cmp "$OIDS_FILE" OUT.actual &&

	verify_objects_in_shared_cache "$OIDS_FILE" &&

	# Technically, we have 1 connection to the origin server
	# for the "gvfs/config" request and 1 to cache server to
	# get the objects, but because we are using the same port
	# for both, keep-alive will handle it.  So 1 connection.
	#
	verify_connection_count 1
'

# The GVFS Protocol POST verb behaves like GET for non-commit objects
# (in that it just returns the requested object), but for commit
# objects POST *also* returns all trees referenced by the commit.
#
# The goal of this test is to confirm that gvfs-helper can send us
# a packfile at all.  So, this test only passes blobs to not blur
# the issue.
#
test_expect_success 'basic: POST origin blobs' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Connect to the origin server (w/o auth) and make
	# multi-object POST request.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.  We verify the number of expected packfile(s) and we
	# individually verify that each requested object is present in the
	# shared cache (and index-pack already verified the integrity of
	# the packfile), so we do not bother to run "git verify-pack -v"
	# and do an exact matchup here.
	#
	verify_received_packfile_count 1 &&

	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE" &&
	verify_connection_count 1
'

# Request a single blob via POST.  Per the GVFS Protocol, the server
# should implicitly send a loose object for it.  Confirm that.
#
test_expect_success 'basic: POST-request a single blob' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Connect to the origin server (w/o auth) and request a single
	# blob via POST.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OID_ONE_BLOB_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "loose <oid>" message for each received
	# loose object.
	#
	sed "s/loose //" <OUT.output | sort >OUT.actual &&
	test_cmp "$OID_ONE_BLOB_FILE" OUT.actual &&

	verify_connection_count 1
'

# Request a single commit via POST.  Per the GVFS Protocol, the server
# should implicitly send us a packfile containing the commit and the
# trees it references.  Confirm that properly handled the receipt of
# the packfile.  (Here, we are testing that asking for a single commit
# via POST yields a packfile rather than a loose object.)
#
# We DO NOT verify that the packfile contains commits/trees and no blobs
# because our test helper doesn't implement the filtering.
#
test_expect_success 'basic: POST-request a single commit' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Connect to the origin server (w/o auth) and request a single
	# commit via POST.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OID_ONE_COMMIT_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.
	#
	verify_received_packfile_count 1 &&

	verify_connection_count 1
'

test_expect_success 'basic: PREFETCH w/o arg gets all' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Without a "since" argument gives us all "ct-*.pack" since the EPOCH
	# because we do not have any prefetch packs locally.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch >OUT.output &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.
	#
	verify_received_packfile_count 3 &&
	verify_prefetch_keeps 1200000000 &&

	stop_gvfs_protocol_server &&
	verify_connection_count 1
'

test_expect_success 'basic: PREFETCH w/ arg' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Ask for cached packfiles NEWER THAN the given time.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch --since="1000000000" >OUT.output &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.
	#
	verify_received_packfile_count 2 &&
	verify_prefetch_keeps 1200000000 &&

	stop_gvfs_protocol_server &&
	verify_connection_count 1
'

test_expect_success 'basic: PREFETCH mayhem no_prefetch_idx' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem no_prefetch_idx &&

	# Request prefetch packs, but tell server to not send any
	# idx files and force gvfs-helper to compute them.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch --since="1000000000" >OUT.output &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.
	#
	verify_received_packfile_count 2 &&
	verify_prefetch_keeps 1200000000 &&

	stop_gvfs_protocol_server &&
	verify_connection_count 1
'

test_expect_success 'basic: PREFETCH up-to-date' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	# Ask for cached packfiles NEWER THAN the given time.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch --since="1000000000" >OUT.output &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.
	#
	verify_received_packfile_count 2 &&
	verify_prefetch_keeps 1200000000 &&

	# Ask again for any packfiles newer than what we have cached locally.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		prefetch >OUT.output &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.
	#
	verify_received_packfile_count 0 &&
	verify_prefetch_keeps 1200000000 &&

	stop_gvfs_protocol_server &&
	verify_connection_count 2
'

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

#################################################################
# Test HTTP Auth
#
#################################################################

test_lazy_prereq CURL_7_75_OR_NEWER '
	git gvfs-helper curl-version ">=" 7.75.0
'

test_expect_success 'HTTP GET Auth on Origin Server' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_401 &&

	# Force server to require auth.
	# Connect to the origin server without auth.
	# Make a single-object GET request.
	# Confirm that it gets a 401 and then retries with auth.
	#
	GIT_CONFIG_NOSYSTEM=1 \
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
	if test_have_prereq CURL_7_75_OR_NEWER
	then
		verify_connection_count 2
	fi
'

test_expect_success 'HTTP POST Auth on Origin Server' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_401 &&

	# Connect to the origin server and make multi-object POST
	# request and verify that it automatically handles the 401.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output &&

	# Stop the server to prevent the verification steps from faulting-in
	# any missing objects.
	#
	stop_gvfs_protocol_server &&

	# gvfs-helper prints a "packfile <path>" message for each received
	# packfile.  We verify the number of expected packfile(s) and we
	# individually verify that each requested object is present in the
	# shared cache (and index-pack already verified the integrity of
	# the packfile), so we do not bother to run "git verify-pack -v"
	# and do an exact matchup here.
	#
	verify_received_packfile_count 1 &&

	verify_objects_in_shared_cache "$OIDS_BLOBS_FILE" &&
	verify_connection_count 2
'

test_expect_success 'HTTP GET Auth on Cache Server' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem http_401 &&

	# Try auth to cache-server.  Note that gvfs-helper *ALWAYS* sends
	# creds to cache-servers, so we will never see the "400 Bad Request"
	# response.  And we are using "trust" mode, so we only expect 1
	# connection to the server.
	#
	GIT_CONFIG_NOSYSTEM=1 \
		git -C "$REPO_T1" gvfs-helper \
			--cache-server=trust \
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
	verify_connection_count 1
'

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


#################################################################
# Duplicate packfile tests.
#
# If we request a fixed set of blobs, we should get a unique packfile
# of the form "vfs-<sha>.{pack,idx}".  It we request that same set
# again, the server should create and send the exact same packfile.
# True web servers might build the custom packfile in random order,
# but our test web server should give us consistent results.
#
# Verify that we can handle the duplicate pack and idx file properly.
#################################################################

test_expect_success 'duplicate: vfs- packfile' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&
	verify_received_packfile_count 1 &&
	verify_vfs_packfile_count 1 &&

	# Re-fetch the same packfile.  We do not care if it replaces
	# first one or if it silently fails to overwrite the existing
	# one.  We just confirm that afterwards we only have 1 packfile.
	#
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&
	verify_received_packfile_count 1 &&
	verify_vfs_packfile_count 1 &&

	stop_gvfs_protocol_server
'

test_expect_success 'duplicate and busy: vfs- packfile' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server &&

	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" \
		>OUT.output \
		2>OUT.stderr &&
	verify_received_packfile_count 1 &&
	verify_vfs_packfile_count 1 &&

	# Re-fetch the same packfile, but hold the existing packfile
	# open for writing on an obscure (and randomly-chosen) file
	# descriptor.
	#
	# This should cause the replacement-install to fail (at least
	# on Windows) with an EBUSY or EPERM or something.
	#
	# Verify that that error is eaten.  We do not care if the
	# replacement is retried or if gvfs-helper simply discards the
	# second instance.  We just confirm that afterwards we only
	# have 1 packfile on disk and that the command "lies" and reports
	# that it created the existing packfile.  (We want the lie because
	# in normal usage, gh-client has already built the packed-git list
	# in memory and is using gvfs-helper to fetch missing objects;
	# gh-client does not care who does the fetch, but it needs to
	# update its packed-git list and restart the object lookup.)
	#
	PACK=$(first_received_packfile_pathname) &&
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=disable \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" \
		>OUT.output \
		2>OUT.stderr \
		9>>"$PACK" &&
	verify_received_packfile_count 1 &&
	verify_vfs_packfile_count 1 &&

	stop_gvfs_protocol_server
'

#################################################################
# Ensure that the SHA of the blob we received matches the SHA of
# the blob we requested.
#################################################################

# Request a loose blob from the server.  Verify that we received
# content matches the requested SHA.
#
test_expect_success 'catch corrupted loose object' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem corrupt_loose &&

	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
			--cache-server=trust \
			--remote=origin \
			get \
			<"$OID_ONE_BLOB_FILE" >OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	# Verify corruption detected.
	# Verify valid blob not included in response to client.

	grep "hash failed for received loose object" OUT.stderr &&

	# Verify that we did not write the corrupted blob to the ODB.

	! verify_objects_in_shared_cache "$OID_ONE_BLOB_FILE" &&
	git -C "$REPO_T1" fsck
'

#################################################################
# Ensure that we can detect when we receive a corrupted packfile
# from the server.  This is not concerned with network IO errors,
# but rather cases when the cache or origin server generates or
# sends an invalid packfile.
#
# For example, if the server throws an exception and writes the
# stack trace to the socket rather than or in addition to the
# packfile content.
#
# Or for example, if the packfile on the server's disk is corrupt
# and it sends it correctly, but the original data was already
# garbage, so the client still has garbage (and retrying won't
# help).
#################################################################

# Send corrupt PACK files w/o IDX files (so that `gvfs-helper`
# must use `index-pack` to create it.  (And as a side-effect,
# validate the PACK file is not corrupt.)
test_expect_success 'prefetch corrupt pack without idx' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem \
		bad_prefetch_pack_sha \
		no_prefetch_idx &&

	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
			--cache-server=disable \
			--remote=origin \
			--no-progress \
			prefetch \
			--max-retries=0 \
			--since="1000000000" \
			>OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server &&

	# Verify corruption detected in pack when building
	# local idx file for it.

	test_grep "error: .* index-pack failed" OUT.stderr
'

# Send corrupt PACK files with IDX files.  Since the cache server
# sends both, `gvfs-helper` might fail to verify both of them.
test_expect_success 'prefetch corrupt pack with corrupt idx' '
	test_when_finished "per_test_cleanup" &&
	start_gvfs_protocol_server_with_mayhem \
		bad_prefetch_pack_sha &&

	test_must_fail \
		git -C "$REPO_T1" gvfs-helper \
			--cache-server=disable \
			--remote=origin \
			--no-progress \
			prefetch \
			--max-retries=0 \
			--since="1000000000" \
			>OUT.output 2>OUT.stderr &&

	stop_gvfs_protocol_server
'

#################################################################
# Tests for gvfs.<verb>.cache-server config.
#
# These tests verify that verb-specific cache-server overrides work
# correctly. We run two servers on different ports:
#   - Server 0 (base port): configured as gvfs.cache-server (default)
#   - Server 1 (base port + 1): configured as gvfs.<verb>.cache-server
#
# For each verb (prefetch, get, post), we verify that:
#   1. When using the verb-specific override, the request goes to server 1
#   2. When using a different verb, the request goes to server 0
#################################################################

test_expect_success 'verb-specific cache-server: prefetch uses gvfs.prefetch.cache-server' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.prefetch.cache-server" &&
	start_gvfs_protocol_server 0 &&
	start_gvfs_protocol_server 1 &&

	# Configure server 0 as default cache-server and server 1 for prefetch.
	git -C "$REPO_T1" config gvfs.cache-server "$(cache_server_url 0)" &&
	git -C "$REPO_T1" config gvfs.prefetch.cache-server "$(cache_server_url 1)" &&

	# Run prefetch - should go to server 1.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--no-progress \
		prefetch >OUT.output 2>OUT.stderr &&

	# Verify server 1 was contacted (prefetch-specific).
	verify_server_was_contacted 1 &&

	# Verify server 0 was NOT contacted.
	verify_server_was_not_contacted 0
'

test_expect_success 'verb-specific cache-server: get does NOT use gvfs.prefetch.cache-server' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.prefetch.cache-server" &&
	start_gvfs_protocol_server 0 &&
	start_gvfs_protocol_server 1 &&

	# Configure server 0 as default cache-server and server 1 for prefetch.
	git -C "$REPO_T1" config gvfs.cache-server "$(cache_server_url 0)" &&
	git -C "$REPO_T1" config gvfs.prefetch.cache-server "$(cache_server_url 1)" &&

	# Run get - should go to server 0 (default), not server 1 (prefetch).
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		get \
		<"$OID_ONE_BLOB_FILE" >OUT.output 2>OUT.stderr &&

	# Verify server 0 was contacted (default cache-server).
	verify_server_was_contacted 0 &&

	# Verify server 1 was NOT contacted (prefetch-specific).
	verify_server_was_not_contacted 1
'

test_expect_success 'verb-specific cache-server: get uses gvfs.get.cache-server' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.get.cache-server" &&
	start_gvfs_protocol_server 0 &&
	start_gvfs_protocol_server 1 &&

	# Configure server 0 as default cache-server and server 1 for get.
	git -C "$REPO_T1" config gvfs.cache-server "$(cache_server_url 0)" &&
	git -C "$REPO_T1" config gvfs.get.cache-server "$(cache_server_url 1)" &&

	# Run get - should go to server 1.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		get \
		<"$OID_ONE_BLOB_FILE" >OUT.output 2>OUT.stderr &&

	# Verify server 1 was contacted (get-specific).
	verify_server_was_contacted 1 &&

	# Verify server 0 was NOT contacted.
	verify_server_was_not_contacted 0
'

test_expect_success 'verb-specific cache-server: prefetch does NOT use gvfs.get.cache-server' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.get.cache-server" &&
	start_gvfs_protocol_server 0 &&
	start_gvfs_protocol_server 1 &&

	# Configure server 0 as default cache-server and server 1 for get.
	git -C "$REPO_T1" config gvfs.cache-server "$(cache_server_url 0)" &&
	git -C "$REPO_T1" config gvfs.get.cache-server "$(cache_server_url 1)" &&

	# Run prefetch - should go to server 0 (default), not server 1 (get).
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--no-progress \
		prefetch >OUT.output 2>OUT.stderr &&

	# Verify server 0 was contacted (default cache-server).
	verify_server_was_contacted 0 &&

	# Verify server 1 was NOT contacted (get-specific).
	verify_server_was_not_contacted 1
'

test_expect_success 'verb-specific cache-server: post uses gvfs.post.cache-server' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.post.cache-server" &&
	start_gvfs_protocol_server 0 &&
	start_gvfs_protocol_server 1 &&

	# Configure server 0 as default cache-server and server 1 for post.
	git -C "$REPO_T1" config gvfs.cache-server "$(cache_server_url 0)" &&
	git -C "$REPO_T1" config gvfs.post.cache-server "$(cache_server_url 1)" &&

	# Run post - should go to server 1.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&

	# Verify server 1 was contacted (post-specific).
	verify_server_was_contacted 1 &&

	# Verify server 0 was NOT contacted.
	verify_server_was_not_contacted 0
'

test_expect_success 'verb-specific cache-server: get does NOT use gvfs.post.cache-server' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.post.cache-server" &&
	start_gvfs_protocol_server 0 &&
	start_gvfs_protocol_server 1 &&

	# Configure server 0 as default cache-server and server 1 for post.
	git -C "$REPO_T1" config gvfs.cache-server "$(cache_server_url 0)" &&
	git -C "$REPO_T1" config gvfs.post.cache-server "$(cache_server_url 1)" &&

	# Run get - should go to server 0 (default), not server 1 (post).
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		get \
		<"$OID_ONE_BLOB_FILE" >OUT.output 2>OUT.stderr &&

	# Verify server 0 was contacted (default cache-server).
	verify_server_was_contacted 0 &&

	# Verify server 1 was NOT contacted (post-specific).
	verify_server_was_not_contacted 1
'

test_expect_success 'verb-specific cache-server: all verbs with different servers' '
	test_when_finished "per_test_cleanup" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.cache-server" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.prefetch.cache-server" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.get.cache-server" &&
	test_when_finished "git -C \"$REPO_T1\" config --unset gvfs.post.cache-server" &&
	start_gvfs_protocol_server 0 &&
	start_gvfs_protocol_server 1 &&
	start_gvfs_protocol_server 2 &&
	start_gvfs_protocol_server 3 &&

	# Configure each verb to use a different server:
	# - server 0: default (unused in this test)
	# - server 1: prefetch
	# - server 2: get
	# - server 3: post
	git -C "$REPO_T1" config gvfs.cache-server "$(cache_server_url 0)" &&
	git -C "$REPO_T1" config gvfs.prefetch.cache-server "$(cache_server_url 1)" &&
	git -C "$REPO_T1" config gvfs.get.cache-server "$(cache_server_url 2)" &&
	git -C "$REPO_T1" config gvfs.post.cache-server "$(cache_server_url 3)" &&

	# Run prefetch - should go to server 1.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--no-progress \
		prefetch >OUT.output 2>OUT.stderr &&
	verify_server_was_contacted 1 &&
	verify_server_was_not_contacted 0 &&
	verify_server_was_not_contacted 2 &&
	verify_server_was_not_contacted 3 &&

	# Clean up shared cache for next verb.
	rm -rf "$SHARED_CACHE_T1"/pack/* &&

	# Run get - should go to server 2.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		get \
		<"$OID_ONE_BLOB_FILE" >OUT.output 2>OUT.stderr &&
	verify_server_was_contacted 2 &&

	# Clean up shared cache for next verb.
	rm -rf "$SHARED_CACHE_T1"/[0-9a-f][0-9a-f]/ &&
	rm -rf "$SHARED_CACHE_T1"/pack/* &&

	# Run post - should go to server 3.
	git -C "$REPO_T1" gvfs-helper \
		--cache-server=trust \
		--remote=origin \
		--no-progress \
		post \
		<"$OIDS_BLOBS_FILE" >OUT.output 2>OUT.stderr &&
	verify_server_was_contacted 3
'

test_done
