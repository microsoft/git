/*
 * built-in fsmonitor daemon
 *
 * Monitor filesystem changes to update the Git index intelligently.
 *
 * Copyright (c) 2019 Johannes Schindelin
 */

#include "builtin.h"
#include "parse-options.h"
#include "fsmonitor.h"

static const char * const builtin_fsmonitor__daemon_usage[] = {
	N_("git fsmonitor--daemon [<options>]"),
	NULL
};

int cmd_fsmonitor__daemon(int argc, const char **argv, const char *prefix)
{
	enum daemon_mode { IS_SUPPORTED = 0 } mode = IS_SUPPORTED;
	struct option options[] = {
		OPT_CMDMODE(0, "is-supported", &mode,
			    N_("determine internal fsmonitor on this platform"),
			    IS_SUPPORTED),
		OPT_END()
	};

	if (argc == 2 && !strcmp(argv[1], "-h"))
		usage_with_options(builtin_fsmonitor__daemon_usage, options);

	argc = parse_options(argc, argv, prefix, options,
			     builtin_fsmonitor__daemon_usage, 0);
	if (argc != 0)
		usage_with_options(builtin_fsmonitor__daemon_usage, options);

	if (mode == IS_SUPPORTED)
		return 1;

	die(_("no native fsmonitor daemon available"));
}
