#!/bin/sh

test_description='gvfs-helper verb-specific cache-server tests'

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-gvfs-helper.sh

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
