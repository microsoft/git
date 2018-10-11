#!/usr/bin/perl
#
# Scrub the variable fields from the normal trace2 output to
# make testing easier.

use strict;
use warnings;

my $space = '\W+';
my $qpath = '\'[^\']*\'';
my $string= '.*';
my $float = '[0-9]*\.[0-9]+([eE][-+]?[0-9]+)?';

my $verb;
my $rest;

# This code assumes that the trace2 data was written with bare
# turned on (which omits the "<clock> <file>:<line>" prefix.

while (<>) {
    # Various messages include an elapsed time in the middle
    # of the message.  Replace the time with a placeholder to
    # simplify our HEREDOC in the test script.
    s/elapsed:$float/elapsed:_TIME_/g;

    if ($_ =~ m/^start/) {
	# The 'start' message lists the contents of argv.  On some
	# platforms (Windows), argv[0] is a canonical absolute path to
	# the EXE rather than the value passed in the shell script.
	# Replace it with a placeholder to simplify our HEREDOC in the
	# test script.
	($verb, $rest) = (m/^(start) $space $qpath $space ($string)/x);
	print "$verb _EXE_ $rest\n";
    }
    elsif ($_ =~ m/^cmd_path/) {
	# Likewise, the 'cmd_path' message breaks out argv[0].
	print "cmd_path _EXE_\n";
    }
    else {
	print "$_";
    }
}
