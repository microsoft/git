/*
 * This is a port of Scalar to C.
 */

#include "cache.h"
#include "gettext.h"
#include "parse-options.h"
#include "config.h"
#include "run-command.h"
#include "strbuf.h"

static const char scalar_usage[] =
	N_("scalar <command> [<options>]\n\n"
	   "Commands: clone, config, diagnose, list\n"
	   "\tregister, run, unregister");

static char *scalar_executable_path;

static int run_git(const char *dir, const char *arg, ...)
{
	struct strvec argv;
	va_list args;
	const char *p;
	int res;

	va_start(args, arg);
	while ((p = va_arg(args, const char *)))
		strvec_push(&argv, p);
	va_end(args);

	res = run_command_v_opt_cd_env(argv.v, RUN_GIT_CMD, dir, NULL);

	strvec_clear(&argv);
	return res;
}

static int is_non_empty_dir(const char *path)
{
	DIR *dir = opendir(path);
	struct dirent *entry;

	if (!dir) {
		if (errno != ENOENT) {
			error_errno(_("could not open directory '%s'"), path);
		}
		return 0;
	}

	while ((entry = readdir(dir))) {
		const char *name = entry->d_name;

		if (strcmp(name, ".") && strcmp(name, "..")) {
			closedir(dir);
			return 1;
		}
	}

	closedir(dir);
	return 0;
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

static int cmd_clone(int argc, const char **argv)
{
	int is_unattended = git_env_bool("Scalar_UNATTENDED", 0);
	char *cache_server_url = NULL, *branch = NULL;
	int single_branch = 0, no_fetch_commits_and_trees = 0;
	char *local_cache_path = NULL;
	int full_clone = 0;
	struct option clone_options[] = {
		OPT_STRING(0, "cache-server-url", &cache_server_url,
			   N_("<url>"),
			   N_("the url or friendly name of the cache server")),
		OPT_STRING('b', "branch", &branch, N_("<branch>"),
			   N_("branch to checkout after clone")),
		OPT_BOOL(0, "single-branch", &single_branch,
			 N_("only download metadata for the branch that will be checked out")),
		OPT_BOOL(0, "no-fetch-commits-and-trees",
			 &no_fetch_commits_and_trees,
			 N_("skip fetching commits and trees after clone")),
		OPT_STRING(0, "local-cache-path", &local_cache_path,
			   N_("<path>"),
			   N_("override the path for the local Scalar cache")),
		OPT_BOOL(0, "full-clone", &full_clone,
			 N_("when cloning, create full working directory")),
		OPT_END(),
	};
	const char * const clone_usage[] = {
		N_("git clone [<options>] [--] <repo> [<dir>]"),
		NULL
	};
	const char *url;
	char *dir, *config_path;
	struct strbuf buf = STRBUF_INIT;
	struct strvec args = STRVEC_INIT;
	int res;

	argc = parse_options(argc, argv, NULL, clone_options, clone_usage,
			     PARSE_OPT_KEEP_DASHDASH |
			     PARSE_OPT_STOP_AT_NON_OPTION);

	if (argc == 2) {
		url = argv[0];
		dir = xstrdup(argv[1]);
	} else if (argc == 1) {
		url = argv[0];

		strbuf_addstr(&buf, url);
		/* Strip trailing slashes, if any */
		while (buf.len > 0 && is_dir_sep(buf.buf[buf.len - 1]))
			strbuf_setlen(&buf, buf.len - 1);
		/* Strip suffix `.git`, if any */
		strbuf_strip_suffix(&buf, ".git");

		dir = find_last_dir_sep(buf.buf);
		if (!dir) {
			die(_("cannot deduce worktree name from '%s'"), url);
		}
		dir = xstrdup(dir + 1);
	} else {
		usage_msg_opt(N_("need a URL"), clone_usage, clone_options);
	}

	/* TODO: verify that '--local-cache-path' isn't inside the src folder */
	/* TODO: CheckNotInsideExistingRepo */

	if (is_non_empty_dir(dir)) {
		die(_("'%s' exists and is not empty"), dir);
	}

	if ((res = run_git(NULL, "init", "--", dir, NULL)))
		goto cleanup;

	/* TODO: trace command-line options, is_unattended, elevated, dir */
	trace2_data_intmax("scalar", the_repository, "unattended",
			   is_unattended);

	/* TODO: handle local cache root */

	/* TODO: check whether to use the GVFS protocol */

	config_path = xstrfmt("%s/.git/config", dir);

	/* TODO: this should be removed, right? */
	/* protocol.version=2 is broken right now. */
	if (git_config_set_in_file_gently(config_path,
					  "protocol.version", "1") ||
	    git_config_set_in_file_gently(config_path,
					  "remote.origin.url", url) ||
	    git_config_set_in_file_gently(config_path,
					  "remote.origin.fetch",
					  /*
					   * TODO: should we respect
					   * single_branch here?
					   */
					  "+refs/heads/*:refs/remotes/origin/*") ||
	    git_config_set_in_file_gently(config_path,
					  "remote.origin.promisor", "true") ||
	    git_config_set_in_file_gently(config_path,
					  "remote.origin.partialCloneFilter",
					  "blob:none"))
		return error(_("could not configure '%s'"), dir);

	if (!full_clone &&
	    (res = run_git(dir, "-c", "core.useGVFSHelper=false",
			   "sparse-checkout", "init", "--cone", NULL)))
		goto cleanup;

	if (set_recommended_config(config_path))
		return error(_("could not configure '%s'"), dir);

	/*
	 * TODO: should we pipe the output and grep for "filtering not
	 * recognized by server", and suppress the error output in
	 * that case?
	 */
	if ((res = run_git(dir, "-c", "core.useGVFSHelper=false", "fetch",
			   "--quiet", "origin", NULL))) {
		warning(_("Partial clone failed; Trying full clone"));

		if (git_config_set_in_file_gently(config_path,
						  "remote.origin.promisor",
						  NULL) ||
		    git_config_set_in_file_gently(config_path,
						  "remote.origin.partialCloneFilter",
						  NULL)) {
			res = error(_("could not configure for full clone"));
			strvec_clear(&args);
			goto cleanup;
		}

		if ((res = run_git(dir, "-c", "core.useGVFSHelper=false",
				   "fetch", "--quiet", "origin", NULL)))
			goto cleanup;
	}


	die("To be continued");

cleanup:
	free(dir);
	strbuf_release(&buf);
	return res;
}

static int cmd_config(int argc, const char **argv)
{
	die(N_("'%s' not yet implemented"), argv[0]);
}

static int cmd_diagnose(int argc, const char **argv)
{
	die(N_("'%s' not yet implemented"), argv[0]);
}

static int cmd_list(int argc, const char **argv)
{
	return run_git(NULL, "config", "--get-all", "scalar.repo", NULL);
}

static int add_or_remove_enlistment(int add)
{
	int res;

	if (!the_repository->worktree)
		die(_("Scalar enlistments require a worktree"));

	res = run_git(NULL, "config", "--global", "--get",
		      "--fixed-value", "scalar.repo", the_repository->worktree, NULL);

	/*
	 * If we want to add and the setting is already there, then do nothing.
	 * If we want to remove and the setting is not there, then do nothing.
	 */
	if ((add && !res) || (!add && res))
		return 0;

	return run_git(NULL, "config", "--global",
		       add ? "--add" : "--unset",
		       "--fixed-value", "scalar.repo",
		       the_repository->worktree, NULL);
}

static int toggle_maintenance(int enable)
{
	return run_git(NULL, "maintenance", enable ? "start" : "unregister",
		       NULL);
}

static int run_config_task(void)
{
	int res = 0;

	res = res || add_or_remove_enlistment(1);
	res = res || set_recommended_config(NULL);
	res = res || toggle_maintenance(1);

	return res;
}

static int cmd_register(int argc, const char **argv)
{
	return run_config_task();
}

static const char scalar_run_usage[] =
	N_("scalar run <task>\n"
	   "\ttasks: all, config, commit-graph,\n"
	   "\t       fetch, loose-objects, pack-files");

static int run_maintenance_task(const char *task)
{
	int res;
	struct strvec args = STRVEC_INIT;

	strvec_pushl(&args, "maintenance", "run", NULL);
	strvec_pushf(&args, "--task=%s", task);

	res = run_command_v_opt(args.v, RUN_GIT_CMD);

	strvec_clear(&args);
	return res;
}

static int run_commit_graph_task(void)
{
	return run_maintenance_task("commit-graph");
}

static int run_fetch_task(void)
{
	return run_maintenance_task("prefetch");
}

static int run_loose_objects_task(void)
{
	return run_maintenance_task("loose-objects");
}

static int run_pack_files_task(void)
{
	return run_maintenance_task("incremental-repack");
}

static int cmd_run(int argc, const char **argv)
{
	if (argc < 2)
		usage(scalar_run_usage);

	if (!strcmp(argv[1], "all")) {
		return run_config_task() ||
		       run_fetch_task() ||
		       run_commit_graph_task() ||
		       run_loose_objects_task() ||
		       run_pack_files_task();
	} else if (!strcmp(argv[1], "config")) {
		return run_config_task();
	} else if (!strcmp(argv[1], "commit-graph")) {
		return run_commit_graph_task();
	} else if (!strcmp(argv[1], "fetch")) {
		return run_fetch_task();
	} else if (!strcmp(argv[1], "loose-objects")) {
		return run_loose_objects_task();
	} else if (!strcmp(argv[1], "pack-files")) {
		return run_pack_files_task();
	}

	usage(scalar_run_usage);
}

static int cmd_unregister(int argc, const char **argv)
{
	int res = 0;

	res = res || add_or_remove_enlistment(0);
	res = res || toggle_maintenance(0);
	return res;
}

struct {
	const char *name;
	int (*fn)(int, const char **);
	int needs_git_repo;
} builtins[] = {
	{ "clone", cmd_clone, 0 },
	{ "config", cmd_config, 1 },
	{ "diagnose", cmd_diagnose, 1 },
	{ "list", cmd_list, 0 },
	{ "register", cmd_register, 1 },
	{ "run", cmd_run, 1 },
	{ "unregister", cmd_unregister, 1 },
	{ NULL, NULL},
};

int cmd_main(int argc, const char **argv)
{
	int i;

	if (argc < 2)
		usage(scalar_usage);

	scalar_executable_path = real_pathdup(argv[0], 0);
	if (!scalar_executable_path)
		die(_("could not determine full path of `scalar`"));

	argv++;
	argc--;

	for (i = 0; builtins[i].name; i++)
		if (!strcmp(builtins[i].name, argv[0])) {
			if (builtins[i].needs_git_repo)
				setup_git_directory();
			return builtins[i].fn(argc, argv);
		}

	usage(scalar_usage);
}
