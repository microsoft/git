#!/bin/sh

test_description='gvfs-helper packfile handling tests'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

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

first_received_packfile_pathname () {
	sed -n "s/packfile //p" <OUT.output | head -1
}

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

test_done
