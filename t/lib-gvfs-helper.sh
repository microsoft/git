# Shared library for gvfs-helper tests
#
# This file is sourced by t579*-gvfs-helper*.sh scripts.
# The sourcing script MUST call:
#   1. . ./test-lib.sh
#   2. . "$TEST_DIRECTORY"/lib-gvfs-helper.sh
#   3. init_gvfs_helper_vars
#   4. test_expect_success 'setup repos' 'setup_gvfs_repos'

# Set the port for t/helper/test-gvfs-protocol.exe from either the
# environment or from the test number of this shell script.
#
test_set_port GIT_TEST_GVFS_PROTOCOL_PORT

# Setup the following repos:
#
#    repo_src:
#        A normal, no-magic, fully-populated clone of something.
#        No GVFS (aka VFS4G).  No Scalar.  No partial-clone.
#        This will be used by "t/helper/test-gvfs-protocol.exe"
#        to serve objects.
#
#    repo_t1:
#        An empty repo with no contents nor commits.  That is,
#        everything is missing.  For the tests based on this repo,
#        we don't care why it is missing objects (or if we could
#        actually use it).  We are only testing explicit object
#        fetching using gvfs-helper.exe in isolation.
#
#    repo_t2:
#        Another empty repo to use after we contaminate t1.
#
REPO_SRC="$(pwd)"/repo_src
REPO_T1="$(pwd)"/repo_t1
REPO_T2="$(pwd)"/repo_t2

# Setup some loopback URLs where test-gvfs-protocol.exe will be
# listening.  We will spawn it directly inside the repo_src directory,
# so we don't need any of the directory mapping or configuration
# machinery found in "git-daemon.exe" or "git-http-backend.exe".
#
# This lets us use the "uri-base" part of the URL (prior to the REST
# API "/gvfs/<token>") to control how our mock server responds.  For
# example, only the origin (main Git) server supports "/gvfs/config".
#
# For example, this means that if we add a remote containing $ORIGIN_URL,
# it will work with gvfs-helper, but not for fetch (without some mapping
# tricks).
#
HOST_PORT=127.0.0.1:$GIT_TEST_GVFS_PROTOCOL_PORT
ORIGIN_URL=http://$HOST_PORT/servertype/origin
CACHE_URL=http://$HOST_PORT/servertype/cache

SHARED_CACHE_T1="$(pwd)"/shared_cache_t1
SHARED_CACHE_T2="$(pwd)"/shared_cache_t2

# The pid-file is created by test-gvfs-protocol.exe when it starts.
# The server will shut down if/when we delete it.  (This is a little
# easier than killing it by PID.)
#
PID_FILE="$(pwd)"/pid-file.pid
SERVER_LOG="$(pwd)"/OUT.server.log

# Helper functions to compute port, pid-file, and log for a given
# port increment. An increment of 0 (or empty) uses the base values.
#
server_port () {
	local instance="${1:-0}"
	echo $(($GIT_TEST_GVFS_PROTOCOL_PORT + "$instance"))
}

server_pid_file () {
	local instance="${1:-0}"
	if test "$instance" -eq 0
	then
		echo "$PID_FILE"
	else
		echo "$(pwd)/pid-file-$instance.pid"
	fi
}

server_log_file () {
	local instance="${1:-0}"
	if test "$instance" -eq 0
	then
		echo "$SERVER_LOG"
	else
		echo "$(pwd)/OUT.server-$instance.log"
	fi
}

# Helper to build a cache-server URL for a given port increment.
#
cache_server_url () {
	local instance="${1:-0}"
	local port=$(server_port "$instance")
	echo "http://127.0.0.1:$port/servertype/cache"
}

PATH="$GIT_BUILD_DIR/t/helper/:$PATH" && export PATH

OIDS_FILE="$(pwd)"/oid_list.txt
OIDS_CT_FILE="$(pwd)"/oid_ct_list.txt
OIDS_BLOBS_FILE="$(pwd)"/oids_blobs_file.txt
OID_ONE_BLOB_FILE="$(pwd)"/oid_one_blob_file.txt
OID_ONE_COMMIT_FILE="$(pwd)"/oid_one_commit_file.txt

# Get a list of available OIDs in repo_src so that we can try to fetch
# them and so that we don't have to hard-code a list of known OIDs.
# This doesn't need to be a complete list -- just enough to drive some
# representative tests.
#
# Optionally require that we find a minimum number of OIDs.
#
get_list_of_oids () {
	git -C "$REPO_SRC" rev-list --objects HEAD | sed 's/ .*//' | sort >"$OIDS_FILE"

	if test $# -eq 1
	then
		actual_nr=$(wc -l <"$OIDS_FILE")
		if test $actual_nr -lt $1
		then
			echo "get_list_of_oids: insufficient data.  Need $1 OIDs."
			return 1
		fi
	fi
	return 0
}

get_list_of_blobs_oids () {
	git -C "$REPO_SRC" ls-tree HEAD | grep ' blob ' | awk "{print \$3}" | sort >"$OIDS_BLOBS_FILE"
	head -1 <"$OIDS_BLOBS_FILE" >"$OID_ONE_BLOB_FILE"
}

get_list_of_commit_and_tree_oids () {
	git -C "$REPO_SRC" cat-file --batch-check --batch-all-objects | awk "/commit|tree/ {print \$1}" | sort >"$OIDS_CT_FILE"

	if test $# -eq 1
	then
		actual_nr=$(wc -l <"$OIDS_CT_FILE")
		if test $actual_nr -lt $1
		then
			echo "get_list_of_commit_and_tree_oids: insufficient data.  Need $1 OIDs."
			return 1
		fi
	fi
	return 0
}

get_one_commit_oid () {
	git -C "$REPO_SRC" rev-parse HEAD >"$OID_ONE_COMMIT_FILE"
	return 0
}

# Create a commits-and-trees packfile for use with "prefetch"
# using the given range of commits.
#
create_commits_and_trees_packfile () {
	if test $# -eq 2
	then
		epoch=$1
		revs=$2
	else
		echo "create_commits_and_trees_packfile: Need 2 args"
		return 1
	fi

	pack_file="$REPO_SRC"/.git/objects/pack/ct-$epoch.pack
	idx_file="$REPO_SRC"/.git/objects/pack/ct-$epoch.idx

	git -C "$REPO_SRC" pack-objects --stdout --revs --filter=blob:none \
		>"$pack_file" <<-EOF
		$revs
	EOF
	git -C "$REPO_SRC" index-pack -o "$idx_file" "$pack_file"
	return 0
}

test_expect_success 'setup repos' '
	test_create_repo "$REPO_SRC" &&
	git -C "$REPO_SRC" branch -M main &&
	#
	# test_commit_bulk() does magic to create a packfile containing
	# the new commits.
	#
	# We create branches in repo_src, but also remember the branch OIDs
	# in files so that we can refer to them in repo_t1, which will not
	# have the commits locally (because we do not clone or fetch).
	#
	test_commit_bulk -C "$REPO_SRC" --filename="batch_a.%s.t" 9 &&
	git -C "$REPO_SRC" branch B1 &&
	git -C "$REPO_SRC" rev-parse refs/heads/main >m1.branch &&
	#
	test_commit_bulk -C "$REPO_SRC" --filename="batch_b.%s.t" 9 &&
	git -C "$REPO_SRC" branch B2 &&
	git -C "$REPO_SRC" rev-parse refs/heads/main >m2.branch &&
	#
	# test_commit() creates commits, trees, tags, and blobs and leave
	# them loose.
	#
	test_config gc.auto 0 &&
	#
	test_commit -C "$REPO_SRC" file1.txt &&
	test_commit -C "$REPO_SRC" file2.txt &&
	test_commit -C "$REPO_SRC" file3.txt &&
	test_commit -C "$REPO_SRC" file4.txt &&
	test_commit -C "$REPO_SRC" file5.txt &&
	test_commit -C "$REPO_SRC" file6.txt &&
	test_commit -C "$REPO_SRC" file7.txt &&
	test_commit -C "$REPO_SRC" file8.txt &&
	test_commit -C "$REPO_SRC" file9.txt &&
	git -C "$REPO_SRC" branch B3 &&
	git -C "$REPO_SRC" rev-parse refs/heads/main >m3.branch &&
	#
	# Create some commits-and-trees-only packfiles for testing prefetch.
	# Set arbitrary EPOCH times to make it easier to test fetch-since.
	#
	create_commits_and_trees_packfile 1000000000 B1 &&
	create_commits_and_trees_packfile 1100000000 B1..B2 &&
	create_commits_and_trees_packfile 1200000000 B2..B3 &&
	#
	# gvfs-helper.exe writes downloaded objects to a shared-cache directory
	# rather than the ODB inside the .git directory.
	#
	mkdir "$SHARED_CACHE_T1" &&
	mkdir "$SHARED_CACHE_T1/pack" &&
	mkdir "$SHARED_CACHE_T1/info" &&
	#
	mkdir "$SHARED_CACHE_T2" &&
	mkdir "$SHARED_CACHE_T2/pack" &&
	mkdir "$SHARED_CACHE_T2/info" &&
	#
	# setup repo_t1 and point all of the gvfs.* values to repo_src.
	#
	test_create_repo "$REPO_T1" &&
	git -C "$REPO_T1" branch -M main &&
	git -C "$REPO_T1" remote add origin $ORIGIN_URL &&
	git -C "$REPO_T1" config --local gvfs.cache-server $CACHE_URL &&
	git -C "$REPO_T1" config --local gvfs.sharedCache "$SHARED_CACHE_T1" &&
	echo "$SHARED_CACHE_T1" >> "$REPO_T1"/.git/objects/info/alternates &&
	#
	test_create_repo "$REPO_T2" &&
	git -C "$REPO_T2" branch -M main &&
	git -C "$REPO_T2" remote add origin $ORIGIN_URL &&
	git -C "$REPO_T2" config --local gvfs.cache-server $CACHE_URL &&
	git -C "$REPO_T2" config --local gvfs.sharedCache "$SHARED_CACHE_T2" &&
	echo "$SHARED_CACHE_T2" >> "$REPO_T2"/.git/objects/info/alternates &&
	#
	#
	#
	cat <<-EOF >creds.txt &&
		username=x
		password=y
	EOF
	cat <<-EOF >creds.sh &&
		#!/bin/sh
		cat "$(pwd)"/creds.txt
	EOF
	chmod 755 creds.sh &&
	git -C "$REPO_T1" config --local credential.helper "!f() { cat \"$(pwd)\"/creds.txt; }; f" &&
	git -C "$REPO_T2" config --local credential.helper "!f() { cat \"$(pwd)\"/creds.txt; }; f" &&
	#
	# Create some test data sets.
	#
	get_list_of_oids 30 &&
	get_list_of_commit_and_tree_oids 30 &&
	get_list_of_blobs_oids &&
	get_one_commit_oid
'

# Stop a gvfs-protocol server.
# Usage: stop_gvfs_protocol_server [<port_increment>]
#
# The optional port_increment (default 0) specifies which server to stop.
# Increment 0 uses the base port, 1 uses base+1, etc.
#
stop_gvfs_protocol_server () {
	local instance="${1:-0}"
	local pid_file=$(server_pid_file "$instance")
	local log_file=$(server_log_file "$instance")

	if ! test -f "$pid_file"
	then
		return 0
	fi
	#
	# The server will shutdown automatically when we delete the pid-file.
	#
	rm -f "$pid_file"
	#
	# Give it a few seconds to shutdown (mainly to completely release the
	# port before the next test start another instance and it attempts to
	# bind to it).
	#
	for k in 0 1 2 3 4
	do
		if grep -q "Starting graceful shutdown" "$log_file"
		then
			return 0
		fi
		sleep 1
	done

	echo "stop_gvfs_protocol_server($instance): timeout waiting for server shutdown"
	return 1
}

# Start a gvfs-protocol server.
# Usage: start_gvfs_protocol_server [<port_increment>]
#
# The optional port_increment (default 0) specifies which server to start.
# Increment 0 uses the base port, 1 uses base+1, etc.
# This allows running multiple servers simultaneously on different ports.
#
start_gvfs_protocol_server () {
	local instance="${1:-0}"
	local port=$(server_port "$instance")
	local pid_file=$(server_pid_file "$instance")
	local log_file=$(server_log_file "$instance")
	#
	# Launch our server into the background in repo_src.
	#
	(
		cd "$REPO_SRC"
		test-gvfs-protocol --verbose \
			--listen=127.0.0.1 \
			--port=$port \
			--reuseaddr \
			--pid-file="$pid_file" \
			2>"$log_file" &
	)
	#
	# Give it a few seconds to get started.
	#
	for k in 0 1 2 3 4
	do
		if test -f "$pid_file"
		then
			return 0
		fi
		sleep 1
	done

	echo "start_gvfs_protocol_server($instance): timeout waiting for server startup"
	return 1
}

start_gvfs_protocol_server_with_mayhem () {
	if test $# -lt 1
	then
		echo "start_gvfs_protocol_server_with_mayhem: need mayhem args"
		return 1
	fi

	mayhem=""
	for k in $*
	do
		mayhem="$mayhem --mayhem=$k"
	done
	#
	# Launch our server into the background in repo_src.
	#
	(
		cd "$REPO_SRC"
		test-gvfs-protocol --verbose \
			--listen=127.0.0.1 \
			--port=$GIT_TEST_GVFS_PROTOCOL_PORT \
			--reuseaddr \
			--pid-file="$PID_FILE" \
			$mayhem \
			2>"$SERVER_LOG" &
	)
	#
	# Give it a few seconds to get started.
	#
	for k in 0 1 2 3 4
	do
		if test -f "$PID_FILE"
		then
			return 0
		fi
		sleep 1
	done

	echo "start_gvfs_protocol_server($instance): timeout waiting for server startup"
	return 1
}

# Verify that a server received at least one connection.
# Usage: verify_server_was_contacted [<port_increment>]
#
verify_server_was_contacted () {
	local instance="${1:-0}"
	local log_file=$(server_log_file "$instance")
	grep -q "Connection from" "$log_file"
}

# Verify that a server was NOT contacted.
# Usage: verify_server_was_not_contacted [<port_increment>]
#
verify_server_was_not_contacted () {
	local instance="${1:-0}"
	local log_file=$(server_log_file "$instance")
	! grep -q "Connection from" "$log_file"
}

# Verify the number of connections from the client.
#
# If keep-alive is working, a series of successful sequential requests to the
# same server should use the same TCP connection, so a simple multi-get would
# only have one connection.
#
# On the other hand, an auto-retry after a network error (mayhem) will have
# more than one for a single object request.
#
# TODO This may generate false alarm when we get to complicated tests, so
# TODO we might only want to use it for basic tests.
#
verify_connection_count () {
	if test $# -eq 1
	then
		expected_nr=$1
	else
		expected_nr=1
	fi

	actual_nr=$(grep -c "Connection from" "$SERVER_LOG")

	if test $actual_nr -ne $expected_nr
	then
		echo "verify_keep_live: expected $expected_nr; actual $actual_nr"
		return 1
	fi
	return 0
}

# Verify that the set of requested objects are present in
# the shared-cache and that there is no corruption.  We use
# cat-file to hide whether the object is packed or loose in
# the test repo.
#
# Usage: <pathname_to_file_of_oids>
#
verify_objects_in_shared_cache () {
	#
	# See if any of the objects are missing from repo_t1.
	#
	git -C "$REPO_T1" cat-file --batch-check <"$1" >OUT.bc_actual || return 1
	test_grep " missing" OUT.bc_actual && return 1
	#
	# See if any of the objects have different sizes or types than repo_src.
	#
	git -C "$REPO_SRC" cat-file --batch-check <"$1" >OUT.bc_expect || return 1
	test_cmp OUT.bc_expect OUT.bc_actual || return 1
	#
	# See if any of the objects are corrupt in repo_t1.  This fully
	# reconstructs the objects and verifies the hash and therefore
	# detects corruption not found by the earlier "batch-check" step.
	#
	git -C "$REPO_T1" cat-file --batch <"$1" >OUT.b_actual || return 1
	#
	# TODO move the shared-cache directory (and/or the
	# TODO .git/objects/info/alternates and temporarily unset
	# TODO gvfs.sharedCache) and repeat the first "batch-check"
	# TODO and make sure that they are ALL missing.
	#
	return 0
}

# gvfs-helper prints a "packfile <path>" message for each received
# packfile to stdout.  Verify that we received the expected number
# of packfiles.
#
verify_received_packfile_count () {
	if test $# -eq 1
	then
		expected_nr=$1
	else
		expected_nr=1
	fi

	actual_nr=$(grep -c "packfile " <OUT.output)

	if test $actual_nr -ne $expected_nr
	then
		echo "verify_received_packfile_count: expected $expected_nr; actual $actual_nr"
		return 1
	fi
	return 0
}

# Verify that we have exactly 1 prefetch .keep file.
# Optionally, verify that it has the given timestamp.
#
verify_prefetch_keeps () {
	count=$(( $(ls -1 "$SHARED_CACHE_T1"/pack/prefetch-*.keep | wc -l) ))
	if test $count -ne 1
	then
		echo "verify_prefetch_keep_file_count: found $count, expected 1."
		return 1
	fi

	if test $# -eq 1
	then
		count=$(( $(ls -1 "$SHARED_CACHE_T1"/pack/prefetch-$1-*.keep | wc -l) ))
		if test $count -ne 1
		then
			echo "verify_prefetch_keep_file_count: did not find expected keep file."
			return 1
		fi
	fi

	return 0
}

# Verify that the number of vfs- packfile present in the shared-cache
# matches our expectations.
#
verify_vfs_packfile_count () {
	count=$(( $(ls -1 "$SHARED_CACHE_T1"/pack/vfs-*.pack | wc -l) ))
	if test $count -ne $1
	then
		echo "verify_vfs_packfile_count: expected $1; actual $count"
		return 1
	fi
	return 0
}

per_test_cleanup () {
	# Stop servers with port increments 0, 1, 2, 3 to handle tests
	# that may use multiple servers.
	for instance in 0 1 2 3
	do
		stop_gvfs_protocol_server "$instance"
	done

	rm -rf "$SHARED_CACHE_T1"/[0-9a-f][0-9a-f]/
	rm -rf "$SHARED_CACHE_T1"/info/*
	rm -rf "$SHARED_CACHE_T1"/pack/*

	rm -rf OUT.*
	return 0
}

# Return the absolute pathname of the first received packfile.
#
first_received_packfile_pathname () {
	fn=$(sed -n '/^packfile/p' <OUT.output | head -1 | sed -n 's/^packfile \(.*\)/\1/p')
	echo "$SHARED_CACHE_T1"/pack/"$fn"
	return 0
}
