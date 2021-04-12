/*
 * This is a port of Scalar to C.
 */

#include "cache.h"
#include "gettext.h"
#include "parse-options.h"
#include "config.h"
#include "run-command.h"

static void setup_enlistment_directory(int argc, const char **argv,
				       const char * const *usagestr,
				       const struct option *options)
{
	if (startup_info->have_repository)
		BUG("gitdir already set up?!?");

	if (argc > 1)
		usage_with_options(usagestr, options);

	if (argc == 1) {
		char *src = xstrfmt("%s/src", argv[0]);
		const char *dir = is_directory(src) ? src : argv[0];

		if (chdir(dir) < 0)
			die_errno(_("could not switch to '%s'"), dir);

		free(src);
	} else {
		/* find the worktree, and ensure that it is named `src` */
		struct strbuf path = STRBUF_INIT;

		if (strbuf_getcwd(&path) < 0)
			die(_("need a working directory"));

		for (;;) {
			size_t len = path.len;

			strbuf_addstr(&path, "/src/.git");
			if (is_git_directory(path.buf)) {
				strbuf_setlen(&path, len);
				strbuf_addstr(&path, "/src");
				if (chdir(path.buf) < 0)
					die_errno(_("could not switch to '%s'"),
						  path.buf);
				strbuf_release(&path);
				break;
			}

			while (len > 0 && !is_dir_sep(path.buf[--len]))
				; /* keep looking for parent directory */

			if (!len)
				die(_("could not find enlistment root"));

			strbuf_setlen(&path, len);
		}
	}

	setup_git_directory();
}

static int run_git(const char *arg, ...)
{
	struct strvec argv = STRVEC_INIT;
	va_list args;
	const char *p;
	int res;

	va_start(args, arg);
	strvec_push(&argv, arg);
	while ((p = va_arg(args, const char *)))
		strvec_push(&argv, p);
	va_end(args);

	res = run_command_v_opt(argv.v, RUN_GIT_CMD);

	strvec_clear(&argv);
	return res;
}

static int set_recommended_config(void)
{
	struct {
		const char *key;
		const char *value;
	} config[] = {
		{ "am.keepCR", "true" },
		{ "core.FSCache", "true" },
		{ "core.multiPackIndex", "true" },
		{ "core.preloadIndex", "true" },
#ifndef WIN32
		{ "core.untrackedCache", "true" },
#else
		/*
		 * Unfortunately, Scalar's Functional Tests demonstrated
		 * that the untracked cache feature is unreliable on Windows
		 * (which is a bummer because that platform would benefit the
		 * most from it). For some reason, freshly created files seem
		 * not to update the directory's `lastModified` time
		 * immediately, but the untracked cache would need to rely on
		 * that.
		 *
		 * Therefore, with a sad heart, we disable this very useful
		 * feature on Windows.
		 */
		{ "core.untrackedCache", "false" },
#endif
		{ "core.bare", "false" },
		{ "core.logAllRefUpdates", "true" },
		{ "credential.https://dev.azure.com.useHttpPath", "true" },
		{ "credential.validate", "false" }, /* GCM4W-only */
		{ "gc.auto", "0" },
		{ "gui.GCWarning", "false" },
		{ "index.threads", "true" },
		{ "index.version", "4" },
		{ "merge.stat", "false" },
		{ "merge.renames", "false" },
		{ "pack.useBitmaps", "false" },
		{ "pack.useSparse", "true" },
		{ "receive.autoGC", "false" },
		{ "reset.quiet", "true" },
		{ "feature.manyFiles", "false" },
		{ "feature.experimental", "false" },
		{ "fetch.unpackLimit", "1" },
		{ "fetch.writeCommitGraph", "false" },
#ifdef WIN32
		{ "http.sslBackend", "schannel" },
#endif
		{ "status.aheadBehind", "false" },
		{ "commitGraph.generationVersion", "1" },
		{ "core.autoCRLF", "false" },
		{ "core.safeCRLF", "false" },
		{ "maintenance.gc.enabled", "false" },
		{ "maintenance.prefetch.enabled", "true" },
		{ "maintenance.prefetch.auto", "0" },
		{ "maintenance.prefetch.schedule", "hourly" },
		{ "maintenance.commit-graph.enabled", "true" },
		{ "maintenance.commit-graph.auto", "0" },
		{ "maintenance.commit-graph.schedule", "hourly" },
		{ "maintenance.loose-objects.enabled", "true" },
		{ "maintenance.loose-objects.auto", "0" },
		{ "maintenance.loose-objects.schedule", "daily" },
		{ "maintenance.incremental-repack.enabled", "true" },
		{ "maintenance.incremental-repack.auto", "0" },
		{ "maintenance.incremental-repack.schedule", "daily" },
		{ NULL, NULL },
	};
	int i;
	char *value;

	for (i = 0; config[i].key; i++) {
		if (git_config_get_string(config[i].key, &value)) {
			trace2_data_string("scalar", the_repository, config[i].key, "created");
			if (git_config_set_gently(config[i].key,
						  config[i].value) < 0)
				return error(_("could not configure %s=%s"),
					     config[i].key, config[i].value);
		} else {
			trace2_data_string("scalar", the_repository, config[i].key, "exists");
			free(value);
		}
	}

	/*
	 * The `log.excludeDecoration` setting is special because we want to
	 * set multiple values.
	 */
	if (git_config_get_string("log.excludeDecoration", &value)) {
		trace2_data_string("scalar", the_repository,
				   "log.excludeDecoration", "created");
		if (git_config_set_multivar_gently("log.excludeDecoration",
						   "refs/scalar/*",
						   CONFIG_REGEX_NONE, 0) ||
		    git_config_set_multivar_gently("log.excludeDecoration",
						   "refs/prefetch/*",
						   CONFIG_REGEX_NONE, 0))
			return error(_("could not configure "
				       "log.excludeDecoration"));
	} else {
		trace2_data_string("scalar", the_repository,
				   "log.excludeDecoration", "exists");
		free(value);
	}

	return 0;
}

static int toggle_maintenance(int enable)
{
	return run_git("maintenance", enable ? "start" : "unregister", NULL);
}

static int add_or_remove_enlistment(int add)
{
	int res;

	if (!the_repository->worktree)
		die(_("Scalar enlistments require a worktree"));

	res = run_git("config", "--global", "--get", "--fixed-value",
		      "scalar.repo", the_repository->worktree, NULL);

	/*
	 * If we want to add and the setting is already there, then do nothing.
	 * If we want to remove and the setting is not there, then do nothing.
	 */
	if ((add && !res) || (!add && res))
		return 0;

	return run_git("config", "--global", add ? "--add" : "--unset",
		       add ? "--no-fixed-value" : "--fixed-value",
		       "scalar.repo", the_repository->worktree, NULL);
}

static int register_dir(void)
{
	int res = add_or_remove_enlistment(1);

	if (!res)
		res = set_recommended_config();

	if (!res)
		res = toggle_maintenance(1);

	return res;
}

static int unregister_dir(void)
{
	int res = 0;

	if (toggle_maintenance(0) < 0)
		res = -1;

	if (add_or_remove_enlistment(0) < 0)
		res = -1;

	return res;
}

static int cmd_list(int argc, const char **argv)
{
	if (argc != 1)
		die(_("`scalar list` does not take arguments"));

	if (run_git("config", "--global", "--get-all", "scalar.repo", NULL) < 0)
		return -1;
	return 0;
}

static int cmd_register(int argc, const char **argv)
{
	struct option options[] = {
		OPT_END(),
	};
	const char * const usage[] = {
		N_("scalar register [<enlistment>]"),
		NULL
	};

	argc = parse_options(argc, argv, NULL, options,
			     usage, 0);

	setup_enlistment_directory(argc, argv, usage, options);

	return register_dir();
}

static int cmd_unregister(int argc, const char **argv)
{
	struct option options[] = {
		OPT_END(),
	};
	const char * const usage[] = {
		N_("scalar unregister [<enlistment>]"),
		NULL
	};

	argc = parse_options(argc, argv, NULL, options,
			     usage, 0);

	setup_enlistment_directory(argc, argv, usage, options);

	return unregister_dir();
}

struct {
	const char *name;
	int (*fn)(int, const char **);
} builtins[] = {
	{ "list", cmd_list },
	{ "register", cmd_register },
	{ "unregister", cmd_unregister },
	{ NULL, NULL},
};

int cmd_main(int argc, const char **argv)
{
	struct strbuf scalar_usage = STRBUF_INIT;
	int i;

	if (argc > 1) {
		argv++;
		argc--;

		for (i = 0; builtins[i].name; i++)
			if (!strcmp(builtins[i].name, argv[0]))
				return !!builtins[i].fn(argc, argv);
	}

	strbuf_addstr(&scalar_usage,
		      N_("scalar <command> [<options>]\n\nCommands:\n"));
	for (i = 0; builtins[i].name; i++)
		strbuf_addf(&scalar_usage, "\t%s\n", builtins[i].name);

	usage(scalar_usage.buf);
}
