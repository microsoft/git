#!/bin/sh

test_description='structured logging tests'

. ./test-lib.sh

if ! test_have_prereq SLOG
then
	skip_all='skipping structured logging tests'
	test_done
fi

LOGFILE=$TRASH_DIRECTORY/test.log

test_expect_success 'setup' '
	test_commit hello &&
	cat >key_cmd_start <<-\EOF &&
	"event":"cmd_start"
	EOF
	cat >key_cmd_exit <<-\EOF &&
	"event":"cmd_exit"
	EOF
	cat >key_exit_code_0 <<-\EOF &&
	"exit_code":0
	EOF
	cat >key_exit_code_129 <<-\EOF &&
	"exit_code":129
	EOF
	cat >key_detail <<-\EOF &&
	"event":"detail"
	EOF
	git config --local slog.pretty false &&
	git config --local slog.path "$LOGFILE"
'

test_expect_success 'basic events' '
	test_when_finished "rm \"$LOGFILE\"" &&
	git status >/dev/null &&
	grep -f key_cmd_start "$LOGFILE" &&
	grep -f key_cmd_exit "$LOGFILE" &&
	grep -f key_exit_code_0 "$LOGFILE"
'

test_expect_success 'basic error code and message' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	test_expect_code 129 git status --xyzzy >/dev/null 2>/dev/null &&
	grep -f key_cmd_exit "$LOGFILE" >event_exit &&
	grep -f key_exit_code_129 event_exit &&
	grep "\"errors\":" event_exit
'

test_lazy_prereq PERLJSON '
	perl -MJSON -e "exit 0"
'

# Let perl parse the resulting JSON and dump it out.
#
# Since the output contains PIDs, SIDs, clock values, and the full path to
# git[.exe] we cannot have a HEREDOC with the expected result, so we look
# for a few key fields.
#
test_expect_success PERLJSON 'parse JSON for basic command' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	git status >/dev/null &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&

	grep "row\[0\]\.version\.slog 0" <parsed_exit &&
	grep "row\[0\]\.argv\[1\] status" <parsed_exit &&
	grep "row\[0\]\.event cmd_exit" <parsed_exit &&
	grep "row\[0\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[0\]\.command status" <parsed_exit
'

test_expect_success PERLJSON 'parse JSON for branch command/sub-command' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	git branch -v >/dev/null &&
	git branch --all >/dev/null &&
	git branch new_branch >/dev/null &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&

	grep "row\[0\]\.version\.slog 0" <parsed_exit &&
	grep "row\[0\]\.argv\[1\] branch" <parsed_exit &&
	grep "row\[0\]\.argv\[2\] -v" <parsed_exit &&
	grep "row\[0\]\.event cmd_exit" <parsed_exit &&
	grep "row\[0\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[0\]\.command branch" <parsed_exit &&
	grep "row\[0\]\.sub_command list" <parsed_exit &&

	grep "row\[1\]\.argv\[1\] branch" <parsed_exit &&
	grep "row\[1\]\.argv\[2\] --all" <parsed_exit &&
	grep "row\[1\]\.event cmd_exit" <parsed_exit &&
	grep "row\[1\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[1\]\.command branch" <parsed_exit &&
	grep "row\[1\]\.sub_command list" <parsed_exit &&

	grep "row\[2\]\.argv\[1\] branch" <parsed_exit &&
	grep "row\[2\]\.argv\[2\] new_branch" <parsed_exit &&
	grep "row\[2\]\.event cmd_exit" <parsed_exit &&
	grep "row\[2\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[2\]\.command branch" <parsed_exit &&
	grep "row\[2\]\.sub_command create" <parsed_exit
'

test_expect_success PERLJSON 'parse JSON for checkout command' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	git checkout new_branch >/dev/null &&
	git checkout master >/dev/null &&
	git checkout -- hello.t >/dev/null &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&

	grep "row\[0\]\.version\.slog 0" <parsed_exit &&
	grep "row\[0\]\.argv\[1\] checkout" <parsed_exit &&
	grep "row\[0\]\.argv\[2\] new_branch" <parsed_exit &&
	grep "row\[0\]\.event cmd_exit" <parsed_exit &&
	grep "row\[0\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[0\]\.command checkout" <parsed_exit &&
	grep "row\[0\]\.sub_command switch_branch" <parsed_exit &&

	grep "row\[1\]\.version\.slog 0" <parsed_exit &&
	grep "row\[1\]\.argv\[1\] checkout" <parsed_exit &&
	grep "row\[1\]\.argv\[2\] master" <parsed_exit &&
	grep "row\[1\]\.event cmd_exit" <parsed_exit &&
	grep "row\[1\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[1\]\.command checkout" <parsed_exit &&
	grep "row\[1\]\.sub_command switch_branch" <parsed_exit &&

	grep "row\[2\]\.version\.slog 0" <parsed_exit &&
	grep "row\[2\]\.argv\[1\] checkout" <parsed_exit &&
	grep "row\[2\]\.argv\[2\] --" <parsed_exit &&
	grep "row\[2\]\.argv\[3\] hello.t" <parsed_exit &&
	grep "row\[2\]\.event cmd_exit" <parsed_exit &&
	grep "row\[2\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[2\]\.command checkout" <parsed_exit &&
	grep "row\[2\]\.sub_command path" <parsed_exit
'

test_expect_success PERLJSON 'turn on all timers, verify some are present' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	git config --local slog.timers 1 &&
	rm -f "$LOGFILE" &&

	git status >/dev/null &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&

	grep "row\[0\]\.version\.slog 0" <parsed_exit &&
	grep "row\[0\]\.argv\[1\] status" <parsed_exit &&
	grep "row\[0\]\.event cmd_exit" <parsed_exit &&
	grep "row\[0\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[0\]\.command status" <parsed_exit &&

	grep "row\[0\]\.timers\.index\.do_read_index\.count" <parsed_exit &&
	grep "row\[0\]\.timers\.index\.do_read_index\.total_us" <parsed_exit &&

	grep "row\[0\]\.timers\.status\.untracked\.count" <parsed_exit &&
	grep "row\[0\]\.timers\.status\.untracked\.total_us" <parsed_exit
'

test_expect_success PERLJSON 'turn on index timers only' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	git config --local slog.timers foo,index,bar &&
	rm -f "$LOGFILE" &&

	git status >/dev/null &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&

	grep "row\[0\]\.version\.slog 0" <parsed_exit &&
	grep "row\[0\]\.argv\[1\] status" <parsed_exit &&
	grep "row\[0\]\.event cmd_exit" <parsed_exit &&
	grep "row\[0\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[0\]\.command status" <parsed_exit &&

	grep "row\[0\]\.timers\.index\.do_read_index\.count" <parsed_exit &&
	grep "row\[0\]\.timers\.index\.do_read_index\.total_us" <parsed_exit &&

	test_expect_code 1 grep "row\[0\]\.timers\.status\.untracked\.count" <parsed_exit &&
	test_expect_code 1 grep "row\[0\]\.timers\.status\.untracked\.total_us" <parsed_exit
'

test_expect_success PERLJSON 'turn on aux-data, verify a few fields' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	echo "hello.t" >.git/info/sparse-checkout &&
	git config --local core.sparsecheckout true &&
	git config --local slog.aux foo,index,bar &&
	rm -f "$LOGFILE" &&

	git checkout HEAD &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&

	grep "row\[0\]\.version\.slog 0" <parsed_exit &&
	grep "row\[0\]\.argv\[1\] checkout" <parsed_exit &&
	grep "row\[0\]\.event cmd_exit" <parsed_exit &&
	grep "row\[0\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[0\]\.command checkout" <parsed_exit &&
	grep "row\[0\]\.sub_command switch_branch" <parsed_exit &&

	# Expect:
	#   row[0].aux.index[<k>][0] cache_nr
	#   row[0].aux.index[<k>][1] 1
	#   row[0].aux.index[<j>][0] sparse_checkout_count
	#   row[0].aux.index[<j>][1] 1
	#
	# But do not assume values for <j> and <k> (in case the sorting changes
	# or other "aux" fields are added later).

	grep "row\[0\]\.aux\.index\[.*\]\[0\] cache_nr" <parsed_exit &&
	grep "row\[0\]\.aux\.index\[.*\]\[0\] sparse_checkout_count" <parsed_exit
'

test_expect_success PERLJSON 'verify child start/end events during clone' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	git config --local slog.aux false &&
	git config --local slog.detail false &&
	git config --local slog.timers false &&
	rm -f "$LOGFILE" &&

	# Clone seems to read the config after it switches to the target repo
	# rather than the source repo, so we have to explicitly set the config
	# settings on the command line.
	git -c slog.path="$LOGFILE" -c slog.detail=true clone . ./clone1 &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&
	grep -f key_detail "$LOGFILE" >event_detail &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&
	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_detail >parsed_detail &&

	grep "row\[0\]\.event cmd_exit" <parsed_exit &&
	grep "row\[0\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[0\]\.command upload-pack" <parsed_exit &&

	grep "row\[1\]\.event cmd_exit" <parsed_exit &&
	grep "row\[1\]\.result\.exit_code 0" <parsed_exit &&
	grep "row\[1\]\.command clone" <parsed_exit &&

	grep "row\[0\]\.detail\.label child_starting" <parsed_detail &&
	grep "row\[0\]\.detail\.data\.child_id 0" <parsed_detail &&
	grep "row\[0\]\.detail\.data\.child_argv\[0\] git-upload-pack" <parsed_detail &&

	grep "row\[1\]\.detail\.label child_ended" <parsed_detail &&
	grep "row\[1\]\.detail\.data\.child_id 0" <parsed_detail &&
	grep "row\[1\]\.detail\.data\.child_argv\[0\] git-upload-pack" <parsed_detail &&
	grep "row\[1\]\.detail\.data\.child_exit_code 0" <parsed_detail
'

. "$TEST_DIRECTORY"/lib-pager.sh
. "$TEST_DIRECTORY"/lib-terminal.sh

test_expect_success 'setup fake pager to test interactive' '
	test_when_finished "rm \"$LOGFILE\" " &&
	sane_unset GIT_PAGER GIT_PAGER_IN_USE &&
	test_unconfig core.pager &&

	PAGER="cat >paginated.out" &&
	export PAGER &&

	test_commit initial
'

test_expect_success TTY 'verify fake pager detected and process marked interactive' '
	test_when_finished "rm \"$LOGFILE\" event_exit" &&
	rm -f paginated.out &&
	rm -f "$LOGFILE" &&

	test_terminal git log &&
	test -e paginated.out &&

	grep -f key_cmd_exit "$LOGFILE" >event_exit &&

	perl "$TEST_DIRECTORY"/t0420/parse_json.perl <event_exit >parsed_exit &&

	grep "row\[0\]\.child_summary\.pager\.count 1" <parsed_exit
'


test_done
