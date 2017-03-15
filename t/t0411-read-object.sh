#!/bin/sh

test_description='tests for read-object hook'

. ./test-lib.sh

test_expect_success 'setup host and guest repos' '
	test_commit zero &&
	hash1=$(git ls-tree HEAD | grep zero.t | cut -f1 | cut -d\  -f3) &&
	git init guest-repo &&
	cd guest-repo &&
	git config core.virtualizeobjects true &&
	write_script .git/hooks/read-object <<-\EOF
		# pass core.virtualizeobjects=false so we dont end up calling the hook proc recursively
		git --git-dir=../.git/ cat-file blob "$1" | git -c core.virtualizeobjects=false hash-object -w --stdin >/dev/null 2>&1
	EOF
'

test_expect_success 'blobs can be retrieved from the host repo' '
	git cat-file blob "$hash1"
'

test_expect_success 'invalid blobs generate errors' '
	test_must_fail git cat-file blob "invalid"
'

test_done
