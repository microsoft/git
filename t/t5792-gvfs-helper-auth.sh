#!/bin/sh

test_description='gvfs-helper authentication tests'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

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

test_done
