#!/bin/sh

test_description='gvfs-helper basic tests'

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

test_done
