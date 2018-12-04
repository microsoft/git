#!/bin/sh

test_description='test trace2 facility (perf target)'
. ./test-lib.sh

# Add t/helper directory to PATH so that we can use a relative
# path to run nested instances of test-tool.exe (see 004child).
# This helps with HEREDOC comparisons later.
TTDIR="$GIT_BUILD_DIR/t/helper/" && export TTDIR
PATH="$TTDIR:$PATH" && export PATH

TT="test-tool" && export TT

# Warning: use of 'test_cmp' may run test-tool.exe and/or git.exe
# Warning: to do the actual diff/comparison, so the HEREDOCs here
# Warning: only cover our actual calls to test-tool and/or git.
# Warning: So you may see extra lines in artifact files when
# Warning: interactively debugging.

# Turn off any inherited trace2 settings for this test.
unset GIT_TR2 GIT_TR2_PERF GIT_TR2_EVENT
unset GIT_TR2_BARE
unset GIT_TR2_CONFIG_PARAMS

V=$(git version | sed -e 's/^git version //') && export V

# There are multiple trace2 targets: normal, perf, and event.
# Trace2 events will/can be written to each active target (subject
# to whatever filtering that target decides to do).
# Test each target independently.

# Enable "perf" trace2 target.
GIT_TR2_PERF="$(pwd)/trace.perf" && export GIT_TR2_PERF
# Enable "bare" feature which turns off the prefix:
#     "<clock> <file>:<line> | <nr_parents> | "
GIT_TR2_BARE=1 && export GIT_TR2_BARE

# Repeat some of the t0210 tests using the perf target stream instead of
# the normal stream.
#
# Tokens here of the form _FIELD_ have been replaced in the observed output.

# Verb 001return
#
# Implicit return from cmd_<verb> function propagates <code>.

test_expect_success 'perf stream, return code 0' '
	test_when_finished "rm trace.perf actual expect" &&
	$TT trace2 001return 0 &&
	perl "$TEST_DIRECTORY/t0211/scrub_perf.perl" <trace.perf >actual &&
	cat >expect <<-EOF &&
		main|version|||||$V
		main|start|||||_EXE_ trace2 001return 0
		main|cmd_verb|||||trace2
		main|exit||_T_ABS_|||code:0
		main|atexit||_T_ABS_|||code:0
	EOF
	test_cmp expect actual
'

test_expect_success 'perf stream, return code 1' '
	test_when_finished "rm trace.perf actual expect" &&
	test_must_fail $TT trace2 001return 1 &&
	perl "$TEST_DIRECTORY/t0211/scrub_perf.perl" <trace.perf >actual &&
	cat >expect <<-EOF &&
		main|version|||||$V
		main|start|||||_EXE_ trace2 001return 1
		main|cmd_verb|||||trace2
		main|exit||_T_ABS_|||code:1
		main|atexit||_T_ABS_|||code:1
	EOF
	test_cmp expect actual
'

# Verb 003error
#
# To the above, add multiple 'error <msg>' events

test_expect_success 'perf stream, error event' '
	test_when_finished "rm trace.perf actual expect" &&
	$TT trace2 003error "hello world" "this is a test" &&
	perl "$TEST_DIRECTORY/t0211/scrub_perf.perl" <trace.perf >actual &&
	cat >expect <<-EOF &&
		main|version|||||$V
		main|start|||||_EXE_ trace2 003error '\''hello world'\'' '\''this is a test'\''
		main|cmd_verb|||||trace2
		main|error|||||hello world
		main|error|||||this is a test
		main|exit||_T_ABS_|||code:0
		main|atexit||_T_ABS_|||code:0
	EOF
	test_cmp expect actual
'

# Verb 004child
#
# Test nested spawning of child processes.
#
# Conceptually, this looks like:
#    P1: TT trace2 004child
#    P2: |--- TT trace2 004child
#    P3:      |--- TT trace2 001return 0
#
# Which should generate events:
#    P1: version
#    P1: start
#    P1: cmd_verb
#    P1: child_start
#        P2: version
#        P2: start
#        P2: cmd_verb
#        P2: child_start
#            P3: version
#            P3: start
#            P3: cmd_verb
#            P3: exit
#            P3: atexit
#        P2: child_exit
#        P2: exit
#        P2: atexit
#    P1: child_exit
#    P1: exit
#    P1: atexit

test_expect_success 'perf stream, child processes' '
	test_when_finished "rm trace.perf actual expect" &&
	$TT trace2 004child $TT trace2 004child $TT trace2 001return 0 &&
	perl "$TEST_DIRECTORY/t0211/scrub_perf.perl" <trace.perf >actual &&
	cat >expect <<-EOF &&
		main|version|||||$V
		main|start|||||_EXE_ trace2 004child $TT trace2 004child $TT trace2 001return 0
		main|cmd_verb|||||trace2
		main|child_start||_T_ABS_|||[ch0] class:? argv: $TT trace2 004child $TT trace2 001return 0
		main|version|||||$V
		main|start|||||_EXE_ trace2 004child $TT trace2 001return 0
		main|cmd_verb|||||trace2
		main|child_start||_T_ABS_|||[ch0] class:? argv: $TT trace2 001return 0
		main|version|||||$V
		main|start|||||_EXE_ trace2 001return 0
		main|cmd_verb|||||trace2
		main|exit||_T_ABS_|||code:0
		main|atexit||_T_ABS_|||code:0
		main|child_exit||_T_ABS_|_T_REL_||[ch0] pid:_PID_ code:0
		main|exit||_T_ABS_|||code:0
		main|atexit||_T_ABS_|||code:0
		main|child_exit||_T_ABS_|_T_REL_||[ch0] pid:_PID_ code:0
		main|exit||_T_ABS_|||code:0
		main|atexit||_T_ABS_|||code:0
	EOF
	test_cmp expect actual
'

test_done
