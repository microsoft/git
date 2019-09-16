#!/bin/sh

test_description='sparse checkout builtin tests'

. ./test-lib.sh

test_expect_success 'setup' '
	git init repo &&
	(
		cd repo &&
		echo "initial" >a &&
		mkdir folder1 folder2 deep &&
		mkdir deep/deeper1 deep/deeper2 &&
		mkdir deep/deeper1/deepest &&
		cp a folder1 &&
		cp a folder2 &&
		cp a deep &&
		cp a deep/deeper1 &&
		cp a deep/deeper2 &&
		cp a deep/deeper1/deepest &&
		git add . &&
		git commit -m "initial commit"
	)
'

test_expect_success 'git sparse-checkout list (empty)' '
	git -C repo sparse-checkout list >list 2>err &&
	test_line_count = 0 list &&
	test_i18ngrep "failed to parse sparse-checkout file; it may not exist" err
'

test_expect_success 'git sparse-checkout list (populated)' '
	test_when_finished rm -f repo/.git/info/sparse-checkout &&
	cat >repo/.git/info/sparse-checkout <<-EOF &&
		/folder1/*
		/deep/
		**/a
		!*bin*
	EOF
	git -C repo sparse-checkout list >list &&
	cat >expect <<-EOF &&
		/folder1/*
		/deep/
		**/a
		!*bin*
	EOF
	test_cmp expect list
'

test_expect_success 'git sparse-checkout init' '
	git -C repo sparse-checkout init &&
	cat >expect <<-EOF &&
		/*
		!/*/*
	EOF
	test_cmp expect repo/.git/info/sparse-checkout &&
	git -C repo config --list >config &&
	test_i18ngrep "core.sparsecheckout=true" config &&
	ls repo >dir  &&
	echo a >expect &&
	test_cmp expect dir
'

test_expect_success 'git sparse-checkout list after init' '
	git -C repo sparse-checkout list >actual &&
	cat >expect <<-EOF &&
		/*
		!/*/*
	EOF
	test_cmp expect actual
'

test_expect_success 'init with existing sparse-checkout' '
	echo "/folder1/*" >> repo/.git/info/sparse-checkout &&
	git -C repo sparse-checkout init &&
	cat >expect <<-EOF &&
		/*
		!/*/*
		/folder1/*
	EOF
	test_cmp expect repo/.git/info/sparse-checkout &&
	ls repo >dir  &&
	cat >expect <<-EOF &&
		a
		folder1
	EOF
	test_cmp expect dir
'

test_expect_success 'clone --sparse' '
	git clone --sparse repo clone &&
	git -C clone sparse-checkout list >actual &&
	cat >expect <<-EOF &&
		/*
		!/*/*
	EOF
	test_cmp expect actual &&
	ls clone >dir &&
	echo a >expect &&
	test_cmp expect dir
'

test_expect_success 'add to existing sparse-checkout' '
	echo "/folder2/*" | git -C repo sparse-checkout add &&
	cat >expect <<-EOF &&
		/*
		!/*/*
		/folder1/*
		/folder2/*
	EOF
	git -C repo sparse-checkout list >actual &&
	test_cmp expect actual &&
	test_cmp expect repo/.git/info/sparse-checkout &&
	ls repo >dir  &&
	cat >expect <<-EOF &&
		a
		folder1
		folder2
	EOF
	test_cmp expect dir
'

test_expect_success 'cone mode: match patterns' '
	git -C repo config --replace-all core.sparseCheckout cone &&
	rm -rf repo/a repo/folder1 repo/folder2 &&
	git -C repo read-tree -mu HEAD &&
	git -C repo reset --hard &&
	ls repo >dir  &&
	cat >expect <<-EOF &&
		a
		folder1
		folder2
	EOF
	test_cmp expect dir
'

test_expect_success 'cone mode: warn on bad pattern' '
	test_when_finished mv sparse-checkout repo/.git/info &&
	cp repo/.git/info/sparse-checkout . &&
	echo "!/deep/deeper/*" >>repo/.git/info/sparse-checkout &&
	git -C repo read-tree -mu HEAD 2>err &&
	test_i18ngrep "unrecognized negative pattern" err
'

test_expect_success 'sparse-checkout disable' '
	git -C repo sparse-checkout disable &&
	test_path_is_missing repo/.git/info/sparse-checkout &&
	git -C repo config --list >config &&
	test_i18ngrep "core.sparsecheckout=false" config &&
	ls repo >dir &&
	cat >expect <<-EOF &&
		a
		deep
		folder1
		folder2
	EOF
	test_cmp expect dir
'

test_expect_success 'cone mode: init and add' '
	git -C repo sparse-checkout init --cone &&
	git -C repo config --list >config &&
	test_i18ngrep "core.sparsecheckout=cone" config &&
	ls repo >dir  &&
	echo a >expect &&
	test_cmp expect dir &&
	echo deep/deeper1/deepest | git -C repo sparse-checkout add &&
	ls repo >dir  &&
	cat >expect <<-EOF &&
		a
		deep
	EOF
	ls repo/deep >dir  &&
	cat >expect <<-EOF &&
		a
		deeper1
	EOF
	ls repo/deep/deeper1 >dir  &&
	cat >expect <<-EOF &&
		a
		deepest
	EOF
	test_cmp expect dir &&
	cat >expect <<-EOF &&
		/*
		!/*/*
		/deep/*
		!/deep/*/*
		/deep/deeper1/*
		!/deep/deeper1/*/*
		/deep/deeper1/deepest/*
	EOF
	test_cmp expect repo/.git/info/sparse-checkout
'
test_done