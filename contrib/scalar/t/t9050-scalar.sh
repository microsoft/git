#!/bin/sh

test_description='test the `scalar` command'

TEST_DIRECTORY=$(pwd)/../../../t
export TEST_DIRECTORY

. ../../../t/test-lib.sh

test_expect_success 'scalar shows a usage' '
        test_expect_code 129 scalar -h
'

test_expect_success 'set up repository to clone' '
	test_commit first &&
	test_commit second &&
	test_commit third &&
	git switch -c parallel first &&
	git config uploadPack.allowFilter true &&
	git config uploadPack.allowAnySHA1InWant true
'

test_expect_success 'scalar clone' '
	second=$(git rev-parse --verify second:second.t) &&
	scalar clone --single-branch "file://$(pwd)" cloned &&
	(
		cd cloned &&
		test_must_fail git rev-list --missing=print $second &&
		git rev-list $second &&
		git cat-file blob $second >actual &&
		echo "second" >expect &&
		test_cmp expect actual
	)
'

test_done
