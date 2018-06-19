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

test_done
