#!/bin/sh

test_description='git blame rename detection control'

. ./test-lib.sh

test_expect_success 'setup test file rename with content changes' '
	git init &&
	echo abc >1.txt &&
	echo def >>1.txt &&
	echo ghi >>1.txt &&
	git add . &&
	git commit -m "Initial commit" &&

	git mv 1.txt 2.txt &&
	echo abc >2.txt &&
	echo 123 >>2.txt &&
	echo ghi >>2.txt &&
	git add . &&
	git commit -m "Rename+edit together"
'

# This test confirms that by default, git blame follows partial-file renames
test_expect_success 'git blame follows inexact renames by default' '
	FIXED_1=$(git rev-parse --short HEAD^) &&
	FIXED_2=$(git rev-parse --short HEAD) &&

	git blame 2.txt >output &&
	grep "$FIXED_1" output | grep -q abc &&
	grep "$FIXED_2" output | grep -q 123 &&
	grep "$FIXED_1" output | grep -q ghi
'

# This test confirms that --no-find-renames or -M0 turns off rename detection
test_expect_success 'git blame can disable rename detection' '
	git blame --no-find-renames 2.txt >output &&
	! grep -q 1.txt output
'

# This test confirms that -M100 only follows exact renames
test_expect_success 'git blame can restrict to exact renames' '
	git blame -M100 2.txt >output &&
	! grep -q 1.txt output
'

# This test checks that blame.renames config works
test_expect_success 'blame.renames=false disables rename detection' '
	git -c blame.renames=false blame 2.txt >output &&
	! grep -q 1.txt output
'

# This test checks that -M with a score works
test_expect_success 'git blame with similarity score follows renames above threshold' '
	# Must follow 1.txt->2.txt rename for abc which are identical
	git blame -M70 2.txt >output &&
	grep "$FIXED_1" output | grep -q abc &&
	# Should not follow for others below threshold
	grep "$FIXED_2" output | grep -q 123 &&
	grep "$FIXED_2" output | grep -q ghi
'

# This test checks that -M overrides blame.renames
test_expect_success '-M overrides blame.renames config' '
	# Using blame.renames=false but -M60
	git -c blame.renames=false blame -M60 2.txt >output &&
	grep "$FIXED_1" output | grep -q abc &&
	# The rest would be below 60% threshold
	grep "$FIXED_2" output | grep -q 123 &&
	grep "$FIXED_2" output | grep -q ghi
'

# This test checks that blame.renames with a score works
test_expect_success 'blame.renames with score controls rename threshold' '
	# Set threshold at 70%, abc is identical so above threshold
	git -c blame.renames=70 blame 2.txt >output &&
	grep "$FIXED_1" output | grep -q abc &&
	# Other lines below threshold
	grep "$FIXED_2" output | grep -q 123 &&
	grep "$FIXED_2" output | grep -q ghi
'

test_done