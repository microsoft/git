#!/bin/sh

test_description='Testing the sq_quote_buf_pretty method in quote.c'
. ./test-lib.sh

test_expect_success 'test method without input string' '
	test_must_fail test-tool quote-buf-pretty
'

test_expect_success 'test null string' '
	cat >expect <<-EOF &&
	'.\'\'.'
	EOF
	test-tool quote-buf-pretty nullString >actual &&
	test_cmp expect actual
'

test_expect_success 'test empty string' '
	cat >expect <<-EOF &&
	'.\'\'.'
	EOF
	test-tool quote-buf-pretty "" >actual &&
	test_cmp expect actual
'

test_expect_success 'string without any punctuation' '
	cat >expect <<-EOF &&
	testString
	EOF
	test-tool quote-buf-pretty testString >actual &&
	test_cmp expect actual
'

test_expect_success 'string with punctuation that does not require special quotes' '
	cat >expect <<-EOF &&
	test+String
	EOF
	test-tool quote-buf-pretty test+String >actual &&
	test_cmp expect actual
'

test_expect_success 'string with punctuation that requires special quotes' '
	cat >expect <<-EOF &&
	'\'test~String\''
	EOF
	test-tool quote-buf-pretty test~String >actual &&
	test_cmp expect actual
'

test_expect_success 'string with punctuation that requires special quotes' '
	cat >expect <<-EOF &&
	'\'test\'\\!\'String\''
	EOF
	test-tool quote-buf-pretty test!String >actual &&
	test_cmp expect actual
'

test_done
