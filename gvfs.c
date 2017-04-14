#include "cache.h"
#include "gvfs.h"
#include "config.h"

static int gvfs_config_loaded;
static int core_gvfs_is_bool;

static int early_core_gvfs_config(const char *var, const char *value, void *data)
{
	if (!strcmp(var, "core.gvfs"))
		core_gvfs = git_config_bool_or_int("core.gvfs", value, &core_gvfs_is_bool);
	return 0;
}

void gvfs_load_config_value(const char *value)
{
	if (gvfs_config_loaded)
		return;

	if (value)
		core_gvfs = git_config_bool_or_int("core.gvfs", value, &core_gvfs_is_bool);
	else if (startup_info->have_repository == 0)
		read_early_config(early_core_gvfs_config, NULL);
	else
		git_config_get_bool_or_int("core.gvfs", &core_gvfs_is_bool, &core_gvfs);

	/* Turn on all bits if a bool was set in the settings */
	if (core_gvfs_is_bool && core_gvfs)
		core_gvfs = -1;

	gvfs_config_loaded = 1;
}

int gvfs_config_is_set(int mask)
{
	gvfs_load_config_value(NULL);
	return (core_gvfs & mask) == mask;
}
