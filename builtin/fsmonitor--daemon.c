#include "builtin.h"
#include "config.h"
#include "parse-options.h"
#include "fsmonitor.h"
#include "fsmonitor-ipc.h"
#include "simple-ipc.h"
#include "khash.h"

#ifdef HAVE_FSMONITOR_DAEMON_BACKEND
static const char * const builtin_fsmonitor__daemon_usage[] = {
	NULL
};

int cmd_fsmonitor__daemon(int argc, const char **argv, const char *prefix)
{
	enum daemon_mode {
		UNDEFINED_MODE,
	} mode = UNDEFINED_MODE;

	struct option options[] = {
		OPT_END()
	};

	if (argc == 2 && !strcmp(argv[1], "-h"))
		usage_with_options(builtin_fsmonitor__daemon_usage, options);

	git_config(git_default_config, NULL);

	argc = parse_options(argc, argv, prefix, options,
			     builtin_fsmonitor__daemon_usage, 0);

	switch (mode) {
	case UNDEFINED_MODE:
	default:
		die(_("Unhandled command mode %d"), mode);
	}
}

#else
int cmd_fsmonitor__daemon(int argc, const char **argv, const char *prefix)
{
	die(_("fsmonitor--daemon not supported on this platform"));
}
#endif
