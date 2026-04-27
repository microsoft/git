#!/bin/sh

test_description='git blame rename configuration options'

. ./test-lib.sh

test_expect_success 'setup' '
	test_write_lines line1 line2 line3 >v1-before-inexact.txt &&
	test_write_lines other1 other2 other3 >unrelated.txt &&
	git add v1-before-inexact.txt unrelated.txt &&
	GIT_AUTHOR_NAME=Original git commit -m "add files" &&

	test_write_lines changed1 line2 line3 >v2-before-exact.txt &&
	git rm v1-before-inexact.txt &&
	git rm unrelated.txt &&
	git add v2-before-exact.txt &&
	GIT_AUTHOR_NAME=Inexact git commit -m "inexact rename with content change" &&

	git mv v2-before-exact.txt v3.txt &&
	GIT_AUTHOR_NAME=Exact git commit -m "exact rename"
'

test_expect_success 'blame follows renames by default' '
	git blame --porcelain v3.txt >output &&
	grep "^filename v1-before-inexact.txt" output
'

test_expect_success 'blame.renames=false disables rename following' '
	git -c blame.renames=false blame --porcelain v3.txt >output &&
	! grep "^filename v1-before-inexact.txt" output &&
	! grep "^filename v2-before-exact.txt" output
'

test_expect_success 'blame.renameThreshold=100% allows exact but skips inexact renames' '
	git -c blame.renameThreshold=100% blame --porcelain v3.txt >output &&
	grep "^filename v2-before-exact.txt" output &&
	! grep "^filename v1-before-inexact.txt" output
'

test_expect_success 'blame.renameLimit=1 skips when sources*destinations exceeds limit' '
	git -c blame.renameLimit=1 blame --porcelain v3.txt >output &&
	grep "^filename v2-before-exact.txt" output &&
	! grep "^filename v1-before-inexact.txt" output
'

test_expect_success 'blame.renameLimit=2 detects with two sources' '
	git -c blame.renameLimit=2 blame --porcelain v3.txt >output &&
	grep "^filename v1-before-inexact.txt" output
'

test_done
