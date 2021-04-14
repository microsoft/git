#!/bin/sh

test_description='test the `scalar` command'

TEST_DIRECTORY=$(pwd)/../../../t
export TEST_DIRECTORY

. ../../../t/test-lib.sh

test_expect_success 'scalar shows a usage' '
        test_expect_code 129 scalar -h
'

test_done
