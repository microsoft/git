#include "builtin.h"
#include "repository.h"
#include "parse-options.h"
#include "run-command.h"

static int platform_specific_upgrade(void)
{
	return 1;
}

static const char builtin_update_microsoft_git_usage[] =
	N_("git update-microsoft-git");

int cmd_update_microsoft_git(int argc, const char **argv, const char *prefix)
{
	if (argc == 2 && !strcmp(argv[1], "-h"))
		usage(builtin_update_microsoft_git_usage);

	return platform_specific_upgrade();
}
