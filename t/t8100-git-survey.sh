#!/bin/sh

test_description='measure repository and report on scaling dimensions'

. ./test-lib.sh

perl -MJSON::PP -e 0 >/dev/null 2>&1 && test_set_prereq JSON_PP

test_expect_success 'verify zero counts before initial commit' '
	test_when_finished "rm -rf data.json actual* expect*" &&

	git survey --json >data.json &&

	# Verify that there are no refs and no objects of any kind.
	#
	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" count <data.json >actual.count &&
	cat >expect.count <<-\EOF &&
		refs.count:0
		commits.count:0
		trees.count:0
		blobs.count:0
	EOF
	test_cmp expect.count actual.count &&

	# Verify that each of the histograms and large-item arrays are empty.
	# This is mainly to test the perl script, since `git survey` will generate
	# JSON with empty objects and arrays and will get parsed into empty hashes
	# and arrays which behave differently in perl.
	#
	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" \
	     commits.mostparents \
	     commits.histparents \
	     trees.histentries \
	     trees.mostentries \
	     blobs.histsize \
	     blobs.largest \
	     <data.json >actual.empty &&
	cat >expect.empty <<-\EOF &&
	EOF
	test_cmp expect.empty actual.empty
'

test_expect_success 'initial commit' '
	test_when_finished "rm -rf data.json actual* expect*" &&

	touch file0 &&
	git add file* &&
	git commit -m "initial" &&

	git survey --json >data.json &&

	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" count <data.json >actual.count &&
	cat >expect.count <<-\EOF &&
		refs.count:1
		commits.count:1
		trees.count:1
		blobs.count:1
	EOF
	test_cmp expect.count actual.count &&

	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" commits.mostparents <data.json >actual-mp &&
	cat >expect-mp <<-\EOF &&
		commits.mostparents[0].nr_parents:0
	EOF
	test_cmp expect-mp actual-mp &&

	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" commits.histparents <data.json >actual-hp &&
	cat >expect-hp <<-\EOF &&
		commits.histparents[P00].count:1
	EOF
	test_cmp expect-hp actual-hp &&

	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" trees.histentries <data.json >actual-he &&
	cat >expect-he <<-\EOF &&
		trees.histentries.Q00.count:1
	EOF
	test_cmp expect-he actual-he &&

	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" trees.mostentries <data.json >actual-me &&
	cat >expect-me <<-\EOF &&
		trees.mostentries[0].nr_entries:1
	EOF
	test_cmp expect-me actual-me &&

	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" blobs.histsize <data.json >actual-hs &&
	cat >expect-hs <<-\EOF &&
		blobs.histsize.H0.count:1
	EOF
	test_cmp expect-hs actual-hs &&

	perl "$TEST_DIRECTORY/t8100/survey_parse_json.perl" blobs.largest <data.json >actual-lb &&
	cat >expect-lb <<-\EOF &&
		blobs.largest[0].size:0
	EOF
	test_cmp expect-lb actual-lb
'

test_done
