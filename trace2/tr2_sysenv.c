#include "cache.h"
#include "config.h"
#include "dir.h"
#include "tr2_sysenv.h"

/*
 * Each entry represents a trace2 setting.
 * See Documentation/technical/api-trace2.txt
 */
struct tr2_sysenv_entry {
	const char *env_var_name;
	const char *git_config_name;

	char *value;
	unsigned int getenv_called : 1;
};

/*
 * This table must match "enum tr2_sysenv_variable" in tr2_sysenv.h.
 * These strings are constant and must match the published names as
 * described in the documentation.
 *
 * We do not define entries for the GIT_TR2_PARENT_* environment
 * variables because they are transient and used to pass information
 * from parent to child git processes, rather than settings.
 */
/* clang-format off */
static struct tr2_sysenv_entry tr2_sysenv_settings[] = {
	{ "GIT_TR2_CONFIG_PARAMS",   "trace2.configparams"     },

	{ "GIT_TR2_DST_DEBUG",       "trace2.destinationdebug" },

	{ "GIT_TR2",                 "trace2.normaltarget"     },
	{ "GIT_TR2_BRIEF",           "trace2.normalbrief"      },

	{ "GIT_TR2_EVENT",           "trace2.eventtarget"      },
	{ "GIT_TR2_EVENT_BRIEF",     "trace2.eventbrief"       },
	{ "GIT_TR2_EVENT_NESTING",   "trace2.eventnesting"     },

	{ "GIT_TR2_PERF",            "trace2.perftarget"       },
	{ "GIT_TR2_PERF_BRIEF",      "trace2.perfbrief"        },
};
/* clang-format on */

static int tr2_sysenv_cb(const char *key, const char *value, void *d)
{
	int k;

	for (k = 0; k < ARRAY_SIZE(tr2_sysenv_settings); k++) {
		if (!strcmp(key, tr2_sysenv_settings[k].git_config_name)) {
			free(tr2_sysenv_settings[k].value);
			tr2_sysenv_settings[k].value = xstrdup(value);
			return 0;
		}
	}

	return 0;
}

/*
 * Load Trace2 settings from the system config (usually "/etc/gitconfig"
 * unless we were built with a runtime-prefix).  These are intended to
 * define the default values for Trace2 as requested by the administrator.
 */
void tr2_sysenv_load(void)
{
	const char *system_config_pathname;
	const char *test_pathname;

	system_config_pathname = git_etc_gitconfig();

	test_pathname = getenv("GIT_TEST_TR2_SYSTEM_CONFIG");
	if (test_pathname) {
		if (!*test_pathname || !strcmp(test_pathname, "0"))
			return; /* disable use of system config */

		/* mock it with given test file */
		system_config_pathname = test_pathname;
	}

	if (file_exists(system_config_pathname))
		git_config_from_file(tr2_sysenv_cb, system_config_pathname,
				     NULL);
}

/*
 * Return the value for the requested setting.  Start with the /etc/gitconfig
 * value and allow the corresponding environment variable to override it.
 */
const char *tr2_sysenv_get(enum tr2_sysenv_variable var)
{
	if (var >= TR2_SYSENV_MUST_BE_LAST)
		BUG("tr2_sysenv_get invalid var '%d'", var);

	if (!tr2_sysenv_settings[var].getenv_called) {
		const char *v = getenv(tr2_sysenv_settings[var].env_var_name);
		if (v && *v) {
			free(tr2_sysenv_settings[var].value);
			tr2_sysenv_settings[var].value = xstrdup(v);
		}
		tr2_sysenv_settings[var].getenv_called = 1;
	}

	return tr2_sysenv_settings[var].value;
}

/*
 * Return a friendly name for this setting that is suitable for printing
 * in an error messages.
 */
const char *tr2_sysenv_display_name(enum tr2_sysenv_variable var)
{
	if (var >= TR2_SYSENV_MUST_BE_LAST)
		BUG("tr2_sysenv_get invalid var '%d'", var);

	return tr2_sysenv_settings[var].env_var_name;
}

void tr2_sysenv_release(void)
{
	int k;

	for (k = 0; k < ARRAY_SIZE(tr2_sysenv_settings); k++)
		free(tr2_sysenv_settings[k].value);
}
