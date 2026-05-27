#!/bin/sh

test_description='virtual file system tests'

. ./test-lib.sh

clean_repo () {
	rm .git/index &&
	git -c core.virtualfilesystem= reset --hard HEAD &&
	git -c core.virtualfilesystem= clean -fd &&
	touch untracked.txt &&
	touch dir1/untracked.txt &&
	touch dir2/untracked.txt
}

test_expect_success 'setup' '
	git branch -M main &&
	mkdir -p .git/hooks/ &&
	cat > .gitignore <<-\EOF &&
		.gitignore
		expect*
		actual*
	EOF
	mkdir -p dir1 &&
	touch dir1/file1.txt &&
	touch dir1/file2.txt &&
	mkdir -p dir2 &&
	touch dir2/file1.txt &&
	touch dir2/file2.txt &&
	git add . &&
	git commit -m "initial" &&
	git config --local core.virtualfilesystem .git/hooks/virtualfilesystem
'

test_expect_success 'test hook parameters and version' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		if test "$#" -ne 1
		then
			echo "$0: Exactly 1 argument expected" >&2
			exit 2
		fi

		if test "$1" != 1
		then
			echo "$0: Unsupported hook version." >&2
			exit 1
		fi
	EOF
	git status &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		exit 3
	EOF
	test_must_fail git status
'

test_expect_success 'verify status is clean' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir2/file1.txt\0"
	EOF
	rm -f .git/index &&
	git checkout -f &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir2/file1.txt\0"
		printf "dir1/file1.txt\0"
		printf "dir1/file2.txt\0"
	EOF
	git status > actual &&
	cat > expected <<-\EOF &&
		On branch main
		nothing to commit, working tree clean
	EOF
	test_cmp expected actual
'

test_expect_success 'verify skip-worktree bit is set for absolute path' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file1.txt\0"
	EOF
	git ls-files -v > actual &&
	cat > expected <<-\EOF &&
		H dir1/file1.txt
		S dir1/file2.txt
		S dir2/file1.txt
		S dir2/file2.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'verify skip-worktree bit is cleared for absolute path' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file2.txt\0"
	EOF
	git ls-files -v > actual &&
	cat > expected <<-\EOF &&
		S dir1/file1.txt
		H dir1/file2.txt
		S dir2/file1.txt
		S dir2/file2.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'verify folder wild cards' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/\0"
	EOF
	git ls-files -v > actual &&
	cat > expected <<-\EOF &&
		H dir1/file1.txt
		H dir1/file2.txt
		S dir2/file1.txt
		S dir2/file2.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'verify folders not included are ignored' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file1.txt\0"
		printf "dir1/file2.txt\0"
	EOF
	mkdir -p dir1/dir2 &&
	touch dir1/a &&
	touch dir1/b &&
	touch dir1/dir2/a &&
	touch dir1/dir2/b &&
	git add . &&
	git ls-files -v > actual &&
	cat > expected <<-\EOF &&
		H dir1/file1.txt
		H dir1/file2.txt
		S dir2/file1.txt
		S dir2/file2.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'verify including one file doesnt include the rest' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file1.txt\0"
		printf "dir1/file2.txt\0"
		printf "dir1/dir2/a\0"
	EOF
	mkdir -p dir1/dir2 &&
	touch dir1/a &&
	touch dir1/b &&
	touch dir1/dir2/a &&
	touch dir1/dir2/b &&
	git add . &&
	git ls-files -v > actual &&
	cat > expected <<-\EOF &&
		H dir1/dir2/a
		H dir1/file1.txt
		H dir1/file2.txt
		S dir2/file1.txt
		S dir2/file2.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'verify files not listed are ignored by git clean -f -x' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "untracked.txt\0"
		printf "dir1/\0"
	EOF
	mkdir -p dir3 &&
	touch dir3/untracked.txt &&
	git clean -f -x &&
	test ! -f untracked.txt &&
	test -d dir1 &&
	test -f dir1/file1.txt &&
	test -f dir1/file2.txt &&
	test ! -f dir1/untracked.txt &&
	test -f dir2/file1.txt &&
	test -f dir2/file2.txt &&
	test -f dir2/untracked.txt &&
	test -d dir3 &&
	test -f dir3/untracked.txt
'

test_expect_success 'verify files not listed are ignored by git clean -f -d -x' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "untracked.txt\0"
		printf "dir1/\0"
		printf "dir3/\0"
	EOF
	mkdir -p dir3 &&
	touch dir3/untracked.txt &&
	git clean -f -d -x &&
	test ! -f untracked.txt &&
	test -d dir1 &&
	test -f dir1/file1.txt &&
	test -f dir1/file2.txt &&
	test ! -f dir1/untracked.txt &&
	test -f dir2/file1.txt &&
	test -f dir2/file2.txt &&
	test -f dir2/untracked.txt &&
	test ! -d dir3 &&
	test ! -f dir3/untracked.txt
'

test_expect_success 'verify folder entries include all files' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/\0"
	EOF
	mkdir -p dir1/dir2 &&
	touch dir1/a &&
	touch dir1/b &&
	touch dir1/dir2/a &&
	touch dir1/dir2/b &&
	git status -su > actual &&
	cat > expected <<-\EOF &&
		?? dir1/a
		?? dir1/b
		?? dir1/dir2/a
		?? dir1/dir2/b
		?? dir1/untracked.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'verify case insensitivity of virtual file system entries' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/a\0"
		printf "Dir1/Dir2/a\0"
		printf "DIR2/\0"
	EOF
	mkdir -p dir1/dir2 &&
	touch dir1/a &&
	touch dir1/b &&
	touch dir1/dir2/a &&
	touch dir1/dir2/b &&
	git -c core.ignorecase=false status -su > actual &&
	cat > expected <<-\EOF &&
		?? dir1/a
	EOF
	test_cmp expected actual &&
	git -c core.ignorecase=true status -su > actual &&
	cat > expected <<-\EOF &&
		?? dir1/a
		?? dir1/dir2/a
		?? dir2/untracked.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'on file created' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file3.txt\0"
	EOF
	touch dir1/file3.txt &&
	git add . &&
	git ls-files -v > actual &&
	cat > expected <<-\EOF &&
		S dir1/file1.txt
		S dir1/file2.txt
		H dir1/file3.txt
		S dir2/file1.txt
		S dir2/file2.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'on file renamed' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file1.txt\0"
		printf "dir1/file3.txt\0"
	EOF
	mv dir1/file1.txt dir1/file3.txt &&
	git status -su > actual &&
	cat > expected <<-\EOF &&
		 D dir1/file1.txt
		?? dir1/file3.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'on file deleted' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file1.txt\0"
	EOF
	rm dir1/file1.txt &&
	git status -su > actual &&
	cat > expected <<-\EOF &&
		 D dir1/file1.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'on file overwritten' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/file1.txt\0"
	EOF
	echo "overwritten" > dir1/file1.txt &&
	git status -su > actual &&
	cat > expected <<-\EOF &&
		 M dir1/file1.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'on folder created' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/dir1/\0"
	EOF
	mkdir -p dir1/dir1 &&
	git status -su > actual &&
	cat > expected <<-\EOF &&
	EOF
	test_cmp expected actual &&
	git clean -fd &&
	test ! -d "/dir1/dir1"
'

test_expect_success 'on folder renamed' '
	clean_repo &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir3/\0"
		printf "dir1/file1.txt\0"
		printf "dir1/file2.txt\0"
		printf "dir3/file1.txt\0"
		printf "dir3/file2.txt\0"
	EOF
	mv dir1 dir3 &&
	git status -su > actual &&
	cat > expected <<-\EOF &&
		 D dir1/file1.txt
		 D dir1/file2.txt
		?? dir3/file1.txt
		?? dir3/file2.txt
		?? dir3/untracked.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'folder with same prefix as file' '
	clean_repo &&
	touch dir1.sln &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/\0"
		printf "dir1.sln\0"
	EOF
	git add dir1.sln &&
	git ls-files -v > actual &&
	cat > expected <<-\EOF &&
		H dir1.sln
		H dir1/file1.txt
		H dir1/file2.txt
		S dir2/file1.txt
		S dir2/file2.txt
	EOF
	test_cmp expected actual
'

test_expect_success 'checkout skips lstat for deleted skip-worktree entries in VFS mode' '
	# When switching branches, entries present in the old tree but absent
	# in the new tree go through deleted_entry() -> verify_absent_if_directory().
	# Without the fix, the tree entry lacks CE_NEW_SKIP_WORKTREE (only
	# src_index entries get that flag), so verify_absent_if_directory()
	# falls through to verify_absent_1() which lstats the path. If a
	# directory exists where the deleted file entry was (simulating a
	# worst-case scenario), the lstat finds it and
	# verify_clean_subdirectory() rejects the checkout due to untracked
	# content inside.
	#
	# With the fix, verify_absent_if_directory() is skipped entirely
	# when VFS mode is active — no lstat, no rejection, checkout completes.
	#
	# Set up two branches: main has dir1/ + dir2/, side has only dir1/
	clean_repo &&

	test_when_finished "rm -rf dir2/file1.txt && git -c core.virtualfilesystem= checkout main" &&

	git -c core.virtualfilesystem= checkout -b side &&
	git -c core.virtualfilesystem= rm -rf dir2 &&
	git -c core.virtualfilesystem= commit -m "remove dir2" &&
	git -c core.virtualfilesystem= checkout main &&

	# Configure VFS hook that returns nothing (0% hydration)
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf ""
	EOF

	# Create a directory where the deleted file entry is, with
	# untracked content inside. This would not happen with a real
	# VFS because the VFS would report the file-to-directory change
	# in the virtualfilesystem hook results, clearing skip-worktree.
	# But it lets us verify that the lstat is not called: without
	# the fix, verify_absent_1() lstats this path, finds a directory,
	# and verify_clean_subdirectory() rejects the checkout because of
	# the untracked file inside.
	rm -f dir2/file1.txt &&
	mkdir -p dir2/file1.txt &&
	echo "untracked" >dir2/file1.txt/trap.txt &&

	# Verify all entries are skip-worktree before checkout
	git ls-files -v >actual &&
	! grep "^H " actual &&

	# Checkout to side branch. Without the fix this fails because
	# verify_absent_1 finds untracked content in the directory at
	# dir2/file1.txt. With the fix the lstat is skipped entirely.
	git checkout side
'

test_expect_success 'checkout <tree> -- <path> preserves skip-worktree in VFS mode' '
	# When "git checkout <tree> -- <path>" updates the index with a
	# different version of a file, update_some() creates a replacement
	# cache entry.  Without the fix, skip-worktree is cleared on the
	# new entry, causing checkout_entry() to try unlink() + write on
	# disk.  For virtual files with no physical NTFS entry, the unlink
	# fails with ENOENT and the command exits 255.
	#
	# With the fix, skip-worktree is preserved from the old index
	# entry when core_virtualfilesystem is set.  The index is updated
	# to the tree entry OID, but checkout_entry() is skipped entirely.
	clean_repo &&

	test_when_finished "git -c core.virtualfilesystem= checkout main" &&

	# Create a second commit with modified content
	git -c core.virtualfilesystem= checkout -b checkout-path-test &&
	echo "modified content" >dir1/file1.txt &&
	git -c core.virtualfilesystem= add dir1/file1.txt &&
	git -c core.virtualfilesystem= commit -m "modify dir1/file1.txt" &&

	# Record the OIDs for verification
	git rev-parse HEAD:dir1/file1.txt >expect_new_oid &&
	git rev-parse HEAD~1:dir1/file1.txt >expect_old_oid &&

	# Configure VFS hook that returns nothing (0% hydration).
	# All entries keep skip-worktree set, simulating virtual files
	# with no physical on-disk representation.
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf ""
	EOF

	# Remove the physical file to simulate a virtual placeholder.
	# With the fix, checkout should update the index without
	# touching the working tree (no file creation).
	# Without the fix, checkout would clear skip-worktree and
	# write the file to disk.
	rm -f dir1/file1.txt &&

	# Checkout the old version of the file from the parent commit.
	git checkout HEAD~1 -- dir1/file1.txt &&

	# Index should have the old (HEAD~1) OID
	git ls-files -s dir1/file1.txt >actual_index &&
	grep "$(cat expect_old_oid)" actual_index &&

	# The file should NOT have been written to disk — the fix
	# preserves skip-worktree so checkout_entry() is skipped.
	# Without the fix, checkout clears skip-worktree and writes
	# the file to disk.
	test_path_is_missing dir1/file1.txt
'

test_expect_success MINGW,FSMONITOR_DAEMON 'virtualfilesystem hook disables built-in FSMonitor' '
	clean_repo &&
	test_config core.usebuiltinfsmonitor true &&
	write_script .git/hooks/virtualfilesystem <<-\EOF &&
		printf "dir1/\0"
	EOF
	git config core.virtualfilesystem .git/hooks/virtualfilesystem &&
	git status &&
	test_must_fail git fsmonitor--daemon status
'

test_done
