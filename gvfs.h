#ifndef GVFS_H
#define GVFS_H

#include "cache.h"
#include "config.h"

/*
 * This file is for the specific settings and methods
 * used for GVFS functionality
 */


/*
 * The list of bits in the core_gvfs setting
 */
#define GVFS_SKIP_SHA_ON_INDEX                      (1 << 0)
#define GVFS_MISSING_OK                             (1 << 2)
#define GVFS_NO_DELETE_OUTSIDE_SPARSECHECKOUT       (1 << 3)
#define GVFS_FETCH_SKIP_REACHABILITY_AND_UPLOADPACK (1 << 4)
#define GVFS_BLOCK_FILTERS_AND_EOL_CONVERSIONS      (1 << 6)

static inline int gvfs_config_is_set(int mask) {
	return (core_gvfs & mask) == mask;
}

static inline int gvfs_config_is_set_any(void) {
	return core_gvfs > 0;
}

static inline void gvfs_load_config_value(const char *value) {
	int is_bool = 0;

	if (value)
		core_gvfs = git_config_bool_or_int("core.gvfs", value, &is_bool);
	else
		git_config_get_bool_or_int("core.gvfs", &is_bool, &core_gvfs);

	/* Turn on all bits if a bool was set in the settings */
	if (is_bool && core_gvfs)
		core_gvfs = -1;
}


static inline int gvfs_config_load_and_is_set(int mask) {
	gvfs_load_config_value(0);
	return gvfs_config_is_set(mask);
}


#endif /* GVFS_H */
