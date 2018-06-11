#include "git-compat-util.h"
#include "environment.h"
#include "gvfs.h"
#include "setup.h"
#include "config.h"

static int gvfs_config_loaded;
static int core_gvfs_is_bool;

static int early_core_gvfs_config(const char *var, const char *value,
				  const struct config_context *ctx, void *cb)
{
	if (!strcmp(var, "core.gvfs"))
		core_gvfs = git_config_bool_or_int("core.gvfs", value, ctx->kvi,
						   &core_gvfs_is_bool);
	return 0;
}

void gvfs_load_config_value(const char *value)
{
	if (value) {
		struct key_value_info default_kvi = KVI_INIT;
		core_gvfs = git_config_bool_or_int("core.gvfs", value, &default_kvi, &core_gvfs_is_bool);
	} else if (startup_info->have_repository == 0)
		read_early_config(early_core_gvfs_config, NULL);
	else
		repo_config_get_bool_or_int(the_repository, "core.gvfs",
					    &core_gvfs_is_bool, &core_gvfs);

	/* Turn on all bits if a bool was set in the settings */
	if (core_gvfs_is_bool && core_gvfs)
		core_gvfs = -1;
}

int gvfs_config_is_set(int mask)
{
	if (!gvfs_config_loaded)
		gvfs_load_config_value(NULL);

	gvfs_config_loaded = 1;
	return (core_gvfs & mask) == mask;
}
