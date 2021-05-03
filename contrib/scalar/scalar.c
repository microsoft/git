/*
 * This is a port of Scalar to C.
 */

#include "cache.h"
#include "gettext.h"
#include "parse-options.h"
#include "config.h"
#include "run-command.h"

static int run_git(const char *dir, const char *arg, ...)
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

	res = run_command_v_opt_cd_env(argv.v, RUN_GIT_CMD, dir, NULL);

	strvec_clear(&argv);
	return res;
}

static int set_recommended_config(const char *file)
{
	struct {
		const char *key;
		const char *value;
	} config[] = {
		{ "am.keepCR", "true" },
		{ "commitGraph.generationVersion", "1" },
		{ "core.autoCRLF", "false" },
		{ "core.FSCache", "true" },
		{ "core.logAllRefUpdates", "true" },
		{ "core.multiPackIndex", "true" },
		{ "core.preloadIndex", "true" },
		{ "core.safeCRLF", "false" },
		{ "credential.validate", "false" },
		{ "feature.manyFiles", "false" },
		{ "feature.experimental", "false" },
		{ "fetch.unpackLimit", "1" },
		{ "fetch.writeCommitGraph", "false" },
		{ "gc.auto", "0" },
		{ "gui.GCWarning", "false" },
		{ "index.threads", "true" },
		{ "index.version", "4" },
		{ "maintenance.auto", "false" },
		{ "merge.stat", "false" },
		{ "merge.renames", "false" },
		{ "pack.useBitmaps", "false" },
		{ "pack.useSparse", "true" },
		{ "receive.autoGC", "false" },
		{ "reset.quiet", "true" },
		{ "status.aheadBehind", "false" },
#ifdef WIN32
		/*
		 * Windows-specific settings.
		 */
		{ "core.untrackedCache", "true" },
		{ "core.filemode", "true" },
#endif
		{ NULL, NULL },
	};
	int i;

	for (i = 0; config[i].key; i++) {
		char *value;

		if (file || git_config_get_string(config[i].key, &value)) {
			trace2_data_string("scalar", the_repository, config[i].key, "created");
			git_config_set_in_file_gently(file, config[i].key,
						      config[i].value);
		} else {
			trace2_data_string("scalar", the_repository, config[i].key, "exists");
			free(value);
		}
	}

	return 0;
}

static int toggle_maintenance(const char *dir, int enable)
{
	return run_git(dir, "maintenance", enable ? "start" : "unregister",
		       NULL);
}

static int add_or_remove_enlistment(const char *dir, int add)
{
	char *p = NULL;
	const char *worktree;
	int res;

	if (dir)
		worktree = p = real_pathdup(dir, 1);
	else if (!the_repository->worktree)
		die(_("Scalar enlistments require a worktree"));
	else
		worktree = the_repository->worktree;

	res = run_git(dir, "config", "--global", "--get",
		      "--fixed-value", "scalar.repo", worktree, NULL);

	/*
	 * If we want to add and the setting is already there, then do nothing.
	 * If we want to remove and the setting is not there, then do nothing.
	 */
	if ((add && !res) || (!add && res))
		return 0;

	return run_git(dir, "config", "--global",
		       add ? "--add" : "--unset",
		       add ? "--no-fixed-value" : "--fixed-value",
		       "scalar.repo", worktree, NULL);
}

static int register_dir(const char *dir)
{
	int res = add_or_remove_enlistment(dir, 1);

	if (!res) {
		char *config_path =
			dir ? xstrfmt("%s/.git/config", dir) : NULL;
		res = set_recommended_config(config_path);
		free(config_path);
	}

	if (!res)
		res = toggle_maintenance(dir, 1);

	return res;
}

static int unregister_dir(const char *dir)
{
	int res = add_or_remove_enlistment(dir, 0);

	if (!res)
		res = toggle_maintenance(dir, 0);

	return res;
}

static int cmd_list(int argc, const char **argv)
{
	if (argc != 1)
		die(_("`scalar list` does not take arguments"));

	return run_git(NULL, "config", "--global",
		       "--get-all", "scalar.repo", NULL);
}

static int cmd_register(int argc, const char **argv)
{
	if (argc != 1 && argc != 2)
		usage(_("scalar register [<worktree>]"));

	return register_dir(argc < 2 ? NULL : argv[1]);
}

static int cmd_unregister(int argc, const char **argv)
{
	if (argc != 1 && argc != 2)
		usage(_("scalar unregister [<worktree>]"));

	return unregister_dir(argc < 2 ? NULL : argv[1]);
}

struct {
	const char *name;
	int (*fn)(int, const char **);
	int needs_git_repo;
} builtins[] = {
	{ "list", cmd_list, 0 },
	{ "register", cmd_register, 1 },
	{ "unregister", cmd_unregister, 1 },
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
			if (!strcmp(builtins[i].name, argv[0])) {
				if (builtins[i].needs_git_repo)
					setup_git_directory();
				return builtins[i].fn(argc, argv);
			}
	}

	strbuf_addstr(&scalar_usage,
		      N_("scalar <command> [<options>]\n\nCommands:\n"));
	for (i = 0; builtins[i].name; i++)
		strbuf_addf(&scalar_usage, "\t%s\n", builtins[i].name);

	usage(scalar_usage.buf);
}
