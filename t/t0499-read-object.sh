#!/bin/sh

test_description='tests for long running read-object process'

. ./test-lib.sh

test_expect_success 'setup host repo with a root commit' '
	test_commit zero &&
	hash1=$(git ls-tree HEAD | grep zero.t | cut -f1 | cut -d\  -f3)
'

test_expect_success 'blobs can be retrieved from the host repo' '
	git init guest-repo &&
	(cd guest-repo &&
	 mkdir -p .git/hooks &&
	 sed "1s|/usr/bin/perl|$PERL_PATH|" \
	   <$TEST_DIRECTORY/t0410/read-object \
	   >.git/hooks/read-object &&
	 chmod +x .git/hooks/read-object &&
	 git config core.virtualizeobjects true &&
	 git cat-file blob "$hash1")
'

test_expect_success 'invalid blobs generate errors' '
	(cd guest-repo &&
	 test_must_fail git cat-file blob "invalid")
'

test_expect_success 'read-object-hook is bypassed when writing objects' '
	(cd guest-repo &&
	 echo hello >hello.txt &&
	 git add hello.txt &&
	 hash="$(git rev-parse --verify :hello.txt)" &&
	 test_grep ! "$hash" .git/read-object-hook.log)
'

test_expect_success 'setup no-fetch commit lookups' '
	git init no-fetch &&
	test_commit -C no-fetch --no-tag parent &&
	parent=$(git -C no-fetch rev-parse HEAD) &&
	test_commit -C no-fetch --no-tag tip &&
	tip=$(git -C no-fetch rev-parse HEAD) &&
	parent_path=no-fetch/.git/objects/$(test_oid_to_path "$parent") &&
	mv "$parent_path" parent-object &&
	mkdir -p no-fetch/.git/hooks &&
	write_script no-fetch/.git/hooks/read-object <<-\EOF
	echo invoked >hook-called
	exit 1
	EOF
'

test_expect_success 'no-fetch commit lookups skip object acquisition' '
	test_write_lines "$tip" "?$parent" >expect &&
	for helper in false true
	do
		env GIT_TEST_COMMIT_GRAPH=0 \
			GIT_TRACE2_EVENT="$PWD/no-fetch-$helper.trace" \
			git -C no-fetch -c core.gvfs=0 -c core.commitGraph=false \
			-c core.useGVFSHelper=$helper \
			-c core.virtualizeObjects=true \
			rev-list --missing=print HEAD >actual &&
		test_cmp expect actual &&
		test_path_is_missing no-fetch/hook-called &&
		test_grep ! child_start "no-fetch-$helper.trace" ||
		return 1
	done
'

test_expect_success 'no-fetch commit lookups still report corruption' '
	: >"$parent_path" &&
	for helper in false true
	do
		test_must_fail \
			env GIT_TEST_COMMIT_GRAPH=0 \
			GIT_TRACE2_EVENT="$PWD/corrupt-$helper.trace" \
			git -C no-fetch \
			-c core.gvfs=0 -c core.commitGraph=false \
			-c core.useGVFSHelper=$helper \
			-c core.virtualizeObjects=true \
			rev-list --missing=print HEAD >actual 2>err &&
		test_grep "fatal: loose object .* is corrupt" err &&
		test_path_is_missing no-fetch/hook-called &&
		test_grep ! child_start "corrupt-$helper.trace" ||
		return 1
	done
'

test_done
