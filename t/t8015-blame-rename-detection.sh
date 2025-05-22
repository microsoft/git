#!/bin/sh

test_description='git blame rename detection control'

. ./test-lib.sh

test_expect_success 'setup test file rename with content changes' '
	test_write_lines abc def ghi >1.txt &&
	git add 1.txt &&
	test_tick &&
	git commit -m "Initial commit" &&

	git mv 1.txt 2.txt &&
	test_write_lines abc 123 ghi >2.txt &&
	git add 2.txt &&
	test_tick &&
	git commit -m "Rename+edit together"
'

# This test confirms that by default, git blame follows partial-file renames
test_expect_success 'git blame follows inexact renames by default' '
	COMMIT1=$(git rev-parse --short HEAD^) &&
	COMMIT2=$(git rev-parse --short HEAD) &&

	git blame 2.txt >output &&
	grep "$COMMIT1" output | grep -q abc &&
	grep "$COMMIT2" output | grep -q 123 &&
	grep "$COMMIT1" output | grep -q ghi
'

# This test confirms that --no-find-renames or -M0 turns off rename detection
test_expect_success 'git blame can disable rename detection' '
	git blame --no-find-renames 2.txt >output &&
	! grep -q 1.txt output
'

# This test checks that blame.renames config works
test_expect_success 'blame.renames=false disables rename detection' '
	git -c blame.renames=false blame 2.txt >output &&
	! grep -q 1.txt output
'

test_done