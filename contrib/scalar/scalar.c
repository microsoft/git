/*
 * This is a port of Scalar to C.
 */

#include "cache.h"
#include "gettext.h"
#include "parse-options.h"
#include "config.h"
#include "run-command.h"
#include "refs.h"
#include "help.h"
#include "dir.h"

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

static int set_recommended_config(int reconfigure)
{
	struct {
		const char *key;
		const char *value;
		int overwrite_on_reconfigure;
	} config[] = {
		/* Required */
		{ "am.keepCR", "true", 1 },
		{ "core.FSCache", "true", 1 },
		{ "core.multiPackIndex", "true", 1 },
		{ "core.preloadIndex", "true", 1 },
#ifndef WIN32
		{ "core.untrackedCache", "true", 1 },
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
		{ "core.untrackedCache", "false", 1 },
#endif
		{ "core.bare", "false", 1 },
		{ "core.logAllRefUpdates", "true", 1 },
		{ "credential.https://dev.azure.com.useHttpPath", "true", 1 },
		{ "credential.validate", "false", 1 }, /* GCM4W-only */
		{ "gc.auto", "0", 1 },
		{ "gui.GCWarning", "false", 1 },
		{ "index.threads", "true", 1 },
		{ "index.version", "4", 1 },
		{ "merge.stat", "false", 1 },
		{ "merge.renames", "false", 1 },
		{ "pack.useBitmaps", "false", 1 },
		{ "pack.useSparse", "true", 1 },
		{ "receive.autoGC", "false", 1 },
		{ "reset.quiet", "true", 1 },
		{ "feature.manyFiles", "false", 1 },
		{ "feature.experimental", "false", 1 },
		{ "fetch.unpackLimit", "1", 1 },
		{ "fetch.writeCommitGraph", "false", 1 },
#ifdef WIN32
		{ "http.sslBackend", "schannel", 1 },
#endif
		/* Optional */
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
		if ((reconfigure && config[i].overwrite_on_reconfigure) ||
		    git_config_get_string(config[i].key, &value)) {
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
		res = set_recommended_config(0);

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

static int stage(const char *git_dir, struct strbuf *buf, const char *path)
{
	struct strbuf cacheinfo = STRBUF_INIT;
	struct child_process cp = CHILD_PROCESS_INIT;
	int res;

	strbuf_addstr(&cacheinfo, "100644,");

	cp.git_cmd = 1;
	strvec_pushl(&cp.args, "--git-dir", git_dir,
		     "hash-object", "-w", "--stdin", NULL);
	res = pipe_command(&cp, buf->buf, buf->len, &cacheinfo, 256, NULL, 0);
	if (!res) {
		strbuf_rtrim(&cacheinfo);
		strbuf_addch(&cacheinfo, ',');
		/* We cannot stage `.git`, use `_git` instead. */
		if (starts_with(path, ".git/"))
			strbuf_addf(&cacheinfo, "_%s", path + 1);
		else
			strbuf_addstr(&cacheinfo, path);

		child_process_init(&cp);
		cp.git_cmd = 1;
		strvec_pushl(&cp.args, "--git-dir", git_dir,
			     "update-index", "--add", "--cacheinfo",
			     cacheinfo.buf, NULL);
		res = run_command(&cp);
	}

	strbuf_release(&cacheinfo);
	return res;
}

static int stage_file(const char *git_dir, const char *path)
{
	struct strbuf buf = STRBUF_INIT;
	int res;

	if (strbuf_read_file(&buf, path, 0) < 0)
		return error(_("could not read '%s'"), path);

	res = stage(git_dir, &buf, path);

	strbuf_release(&buf);
	return res;
}

static int stage_directory(const char *git_dir, const char *path, int recurse)
{
	int at_root = !*path;
	DIR *dir = opendir(at_root ? "." : path);
	struct dirent *e;
	struct strbuf buf = STRBUF_INIT;
	size_t len;
	int res = 0;

	if (!dir)
		return error(_("could not open directory '%s'"), path);

	if (!at_root)
		strbuf_addf(&buf, "%s/", path);
	len = buf.len;

	while (!res && (e = readdir(dir))) {
		if (!strcmp(".", e->d_name) || !strcmp("..", e->d_name))
			continue;

		strbuf_setlen(&buf, len);
		strbuf_addstr(&buf, e->d_name);

		if ((e->d_type == DT_REG && stage_file(git_dir, buf.buf)) ||
		    (e->d_type == DT_DIR && recurse &&
		     stage_directory(git_dir, buf.buf, recurse)))
			res = -1;
	}

	closedir(dir);
	strbuf_release(&buf);
	return res;
}

static int index_to_zip(const char *git_dir)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf oid = STRBUF_INIT;

	cp.git_cmd = 1;
	strvec_pushl(&cp.args, "--git-dir", git_dir, "write-tree", NULL);
	if (pipe_command(&cp, NULL, 0, &oid, the_hash_algo->hexsz + 1,
			 NULL, 0))
		return error(_("could not write temporary tree object"));

	strbuf_rtrim(&oid);
	child_process_init(&cp);
	cp.git_cmd = 1;
	strvec_pushl(&cp.args, "--git-dir", git_dir, "archive", "-o", NULL);
	strvec_pushf(&cp.args, "%s.zip", git_dir);
	strvec_pushl(&cp.args, oid.buf, "--", NULL);
	strbuf_release(&oid);
	return run_command(&cp);
}

#ifndef WIN32
#include <sys/statvfs.h>
#endif

static int get_disk_info(struct strbuf *out)
{
#ifdef WIN32
	struct strbuf buf = STRBUF_INIT;
	char volume_name[MAX_PATH], fs_name[MAX_PATH];
	DWORD serial_number, component_length, flags;
	ULARGE_INTEGER avail2caller, total, avail;

	strbuf_realpath(&buf, ".", 1);
	if (!GetDiskFreeSpaceExA(buf.buf, &avail2caller, &total, &avail)) {
		error(_("could not determine free disk size for '%s'"),
		      buf.buf);
		strbuf_release(&buf);
		return -1;
	}

	strbuf_setlen(&buf, offset_1st_component(buf.buf));
	if (!GetVolumeInformationA(buf.buf, volume_name, sizeof(volume_name),
				   &serial_number, &component_length, &flags,
				   fs_name, sizeof(fs_name))) {
		error(_("could not get info for '%s'"), buf.buf);
		strbuf_release(&buf);
		return -1;
	}
	strbuf_addf(out, "Available space on '%s': ", buf.buf);
	strbuf_humanise_bytes(out, avail2caller.QuadPart);
	strbuf_addch(out, '\n');
	strbuf_release(&buf);
#else
	struct strbuf buf = STRBUF_INIT;
	struct statvfs stat;

	strbuf_realpath(&buf, ".", 1);
	if (statvfs(buf.buf, &stat) < 0) {
		error_errno(_("could not determine free disk size for '%s'"),
			    buf.buf);
		strbuf_release(&buf);
		return -1;
	}

	strbuf_addf(out, "Available space on '%s': ", buf.buf);
	strbuf_humanise_bytes(out, st_mult(stat.f_bsize, stat.f_bavail));
	strbuf_addf(out, " (mount flags 0x%lx)\n", stat.f_flag);
	strbuf_release(&buf);
#endif
	return 0;
}

/* printf-style interface, expects `<key>=<value>` argument */
static int set_config(const char *fmt, ...)
{
	struct strbuf buf = STRBUF_INIT;
	char *value;
	int res;
	va_list args;

	va_start(args, fmt);
	strbuf_vaddf(&buf, fmt, args);
	va_end(args);

	value = strchr(buf.buf, '=');
	if (value)
		*(value++) = '\0';
	res = git_config_set_gently(buf.buf, value);
	strbuf_release(&buf);

	return res;
}

static char *remote_default_branch(const char *url)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf out = STRBUF_INIT;

	cp.git_cmd = 1;
	strvec_pushl(&cp.args, "ls-remote", "--symref", url, "HEAD", NULL);
	strbuf_addstr(&out, "-\n");
	if (!pipe_command(&cp, NULL, 0, &out, 0, NULL, 0)) {
		char *ref = out.buf;

		while ((ref = strstr(ref + 1, "\nref: "))) {
			const char *p;
			char *head, *branch;

			ref += strlen("\nref: ");
			head = strstr(ref, "\tHEAD");

			if (!head || memchr(ref, '\n', head - ref))
				continue;

			if (skip_prefix(ref, "refs/heads/", &p)) {
				branch = xstrndup(p, head - p);
				strbuf_release(&out);
				return branch;
			}

			error(_("remote HEAD is not a branch: '%.*s'"),
			      (int)(head - ref), ref);
			strbuf_release(&out);
			return NULL;
		}
	}
	warning(_("failed to get default branch name from remote; "
		  "using local default"));
	strbuf_reset(&out);

	child_process_init(&cp);
	cp.git_cmd = 1;
	strvec_pushl(&cp.args, "symbolic-ref", "--short", "HEAD", NULL);
	if (!pipe_command(&cp, NULL, 0, &out, 0, NULL, 0)) {
		strbuf_trim(&out);
		return strbuf_detach(&out, NULL);
	}

	strbuf_release(&out);
	error(_("failed to get default branch name"));
	return NULL;
}

static int cmd_clone(int argc, const char **argv)
{
	const char *branch = NULL;
	int no_fetch_commits_and_trees = 0, full_clone = 0, single_branch = 0;
	struct option clone_options[] = {
		OPT_STRING('b', "branch", &branch, N_("<branch>"),
			   N_("branch to checkout after clone")),
		OPT_BOOL(0, "no-fetch-commits-and-trees",
			 &no_fetch_commits_and_trees,
			 N_("skip fetching commits and trees after clone")),
		OPT_BOOL(0, "full-clone", &full_clone,
			 N_("when cloning, create full working directory")),
		OPT_BOOL(0, "single-branch", &single_branch,
			 N_("only download metadata for the branch that will "
			    "be checked out")),
		OPT_END(),
	};
	const char * const clone_usage[] = {
		N_("scalar clone [<options>] [--] <repo> [<dir>]"),
		NULL
	};
	const char *url;
	char *enlistment = NULL, *dir = NULL;
	struct strbuf buf = STRBUF_INIT;
	int res;

	argc = parse_options(argc, argv, NULL, clone_options, clone_usage, 0);

	if (argc == 2) {
		url = argv[0];
		enlistment = xstrdup(argv[1]);
	} else if (argc == 1) {
		url = argv[0];

		strbuf_addstr(&buf, url);
		/* Strip trailing slashes, if any */
		while (buf.len > 0 && is_dir_sep(buf.buf[buf.len - 1]))
			strbuf_setlen(&buf, buf.len - 1);
		/* Strip suffix `.git`, if any */
		strbuf_strip_suffix(&buf, ".git");

		enlistment = find_last_dir_sep(buf.buf);
		if (!enlistment) {
			die(_("cannot deduce worktree name from '%s'"), url);
		}
		enlistment = xstrdup(enlistment + 1);
	} else {
		usage_msg_opt(N_("need a URL"), clone_usage, clone_options);
	}

	if (is_directory(enlistment))
		die(_("directory '%s' exists already"), enlistment);

	dir = xstrfmt("%s/src", enlistment);

	strbuf_reset(&buf);
	if (branch)
		strbuf_addf(&buf, "init.defaultBranch=%s", branch);
	else {
		char *b = repo_default_branch_name(the_repository, 1);
		strbuf_addf(&buf, "init.defaultBranch=%s", b);
		free(b);
	}

	if ((res = run_git("-c", buf.buf, "init", "--", dir, NULL)))
		goto cleanup;

	if (chdir(dir) < 0) {
		res = error_errno(_("could not switch to '%s'"), dir);
		goto cleanup;
	}

	setup_git_directory();

	/* common-main already logs `argv` */
	trace2_data_string("scalar", the_repository, "dir", dir);

	if (!branch && !(branch = remote_default_branch(url))) {
		res = error(_("failed to get default branch for '%s'"), url);
		goto cleanup;
	}

	if (set_config("remote.origin.url=%s", url) ||
	    set_config("remote.origin.fetch="
		    "+refs/heads/%s:refs/remotes/origin/%s",
		    single_branch ? branch : "*",
		    single_branch ? branch : "*") ||
	    set_config("remote.origin.promisor=true") ||
	    set_config("remote.origin.partialCloneFilter=blob:none")) {
		res = error(_("could not configure remote in '%s'"), dir);
		goto cleanup;
	}

	if (!full_clone &&
	    (res = run_git("sparse-checkout", "init", "--cone", NULL)))
		goto cleanup;

	if (set_recommended_config(0))
		return error(_("could not configure '%s'"), dir);

	if ((res = run_git("fetch", "--quiet", "origin", NULL))) {
		warning(_("Partial clone failed; Trying full clone"));

		if (set_config("remote.origin.promisor") ||
		    set_config("remote.origin.partialCloneFilter")) {
			res = error(_("could not configure for full clone"));
			goto cleanup;
		}

		if ((res = run_git("fetch", "--quiet", "origin", NULL)))
			goto cleanup;
	}

	if ((res = set_config("branch.%s.remote=origin", branch)))
		goto cleanup;
	if ((res = set_config("branch.%s.merge=refs/heads/%s",
			      branch, branch)))
		goto cleanup;

	strbuf_reset(&buf);
	strbuf_addf(&buf, "origin/%s", branch);
	res = run_git("checkout", "-f", "-t", buf.buf, NULL);
	if (res)
		goto cleanup;

	res = register_dir();

cleanup:
	free(enlistment);
	free(dir);
	strbuf_release(&buf);
	return res;
}

/*
 * Dummy implementation; Using `get_version_info()` would cause a link error
 * without this.
 */
void load_builtin_commands(const char *prefix, struct cmdnames *cmds)
{
	die("not implemented");
}

static int cmd_diagnose(int argc, const char **argv)
{
	struct option options[] = {
		OPT_END(),
	};
	const char * const usage[] = {
		N_("scalar diagnose [<enlistment>]"),
		NULL
	};
	struct strbuf tmp_dir = STRBUF_INIT;
	time_t now = time(NULL);
	struct tm tm;
	struct strbuf path = STRBUF_INIT, buf = STRBUF_INIT;
	int res = 0;

	argc = parse_options(argc, argv, NULL, options,
			     usage, 0);

	setup_enlistment_directory(argc, argv, usage, options);

	strbuf_addstr(&buf, "../.scalarDiagnostics/scalar_");
	strbuf_addftime(&buf, "%Y%m%d_%H%M%S", localtime_r(&now, &tm), 0, 0);
	if (run_git("init", "-q", "-b", "dummy", "--bare", buf.buf, NULL)) {
		res = error(_("could not initialize temporary repository: %s"),
			    buf.buf);
		goto diagnose_cleanup;
	}
	strbuf_realpath(&tmp_dir, buf.buf, 1);

	strbuf_reset(&buf);
	strbuf_addf(&buf, "Collecting diagnostic info into temp folder %s\n\n",
		    tmp_dir.buf);

	get_version_info(&buf, 1);

	strbuf_addf(&buf, "Enlistment root: %s\n", the_repository->worktree);
	get_disk_info(&buf);
	fwrite(buf.buf, buf.len, 1, stdout);

	if ((res = stage(tmp_dir.buf, &buf, "diagnostics.log")))
		goto diagnose_cleanup;

	if ((res = stage_directory(tmp_dir.buf, ".git", 0)) ||
	    (res = stage_directory(tmp_dir.buf, ".git/hooks", 0)) ||
	    (res = stage_directory(tmp_dir.buf, ".git/info", 0)) ||
	    (res = stage_directory(tmp_dir.buf, ".git/logs", 1)) ||
	    (res = stage_directory(tmp_dir.buf, ".git/objects/info", 0)))
		goto diagnose_cleanup;

	res = index_to_zip(tmp_dir.buf);

	if (!res)
		res = remove_dir_recursively(&tmp_dir, 0);

	if (!res)
		printf("\n"
		       "Diagnostics complete.\n"
		       "All of the gathered info is captured in '%s.zip'\n",
		       tmp_dir.buf);

diagnose_cleanup:
	strbuf_release(&tmp_dir);
	strbuf_release(&path);
	strbuf_release(&buf);

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

static int get_scalar_repos(const char *key, const char *value, void *data)
{
	struct string_list *list = data;

	if (!strcmp(key, "scalar.repo"))
		string_list_append(list, value);

	return 0;
}

static int cmd_reconfigure(int argc, const char **argv)
{
	int all = 0;
	struct option options[] = {
		OPT_BOOL('a', "all", &all,
			 N_("reconfigure all registered enlistments")),
		OPT_END(),
	};
	const char * const usage[] = {
		N_("scalar reconfigure [--all | <enlistment>]"),
		NULL
	};
	struct string_list scalar_repos = STRING_LIST_INIT_DUP;
	int i, res = 0;
	struct repository r = { NULL };
	struct strbuf commondir = STRBUF_INIT, gitdir = STRBUF_INIT;

	argc = parse_options(argc, argv, NULL, options,
			     usage, 0);

	if (!all) {
		setup_enlistment_directory(argc, argv, usage, options);

		return set_recommended_config(1);
	}

	if (argc > 0)
		usage_msg_opt(_("--all or <enlistment>, but not both"),
			      usage, options);

	git_config(get_scalar_repos, &scalar_repos);

	for (i = 0; i < scalar_repos.nr; i++) {
		const char *dir = scalar_repos.items[i].string;

		strbuf_reset(&commondir);
		strbuf_reset(&gitdir);

		if (chdir(dir) < 0) {
			warning_errno(_("could not switch to '%s'"), dir);
			res = -1;
		} else if (discover_git_directory(&commondir, &gitdir) < 0) {
			warning_errno(_("Git repository gone in '%s'"), dir);
			res = -1;
		} else {
			git_config_clear();

			the_repository = &r;
			r.commondir = commondir.buf;
			r.gitdir = gitdir.buf;

			if (set_recommended_config(1) < 0)
				res = -1;
		}
	}

	string_list_clear(&scalar_repos, 1);
	strbuf_release(&commondir);
	strbuf_release(&gitdir);

	return res;
}

static int cmd_run(int argc, const char **argv)
{
	struct option options[] = {
		OPT_END(),
	};
	struct {
		const char *arg, *task;
	} tasks[] = {
		{ "config", NULL },
		{ "commit-graph", "commit-graph" },
		{ "fetch", "prefetch" },
		{ "loose-objects", "loose-objects" },
		{ "pack-files", "incremental-repack" },
		{ NULL, NULL }
	};
	struct strbuf buf = STRBUF_INIT;
	const char *usagestr[] = { NULL, NULL };
	int i;

	strbuf_addstr(&buf, N_("scalar run <task> [<enlistment>]\nTasks:\n"));
	for (i = 0; tasks[i].arg; i++)
		strbuf_addf(&buf, "\t%s\n", tasks[i].arg);
	usagestr[0] = buf.buf;

	argc = parse_options(argc, argv, NULL, options,
			     usagestr, 0);

	if (argc == 0)
		usage_with_options(usagestr, options);

	if (!strcmp("all", argv[0]))
		i = -1;
	else {
		for (i = 0; tasks[i].arg && strcmp(tasks[i].arg, argv[0]); i++)
			; /* keep looking for the task */

		if (i > 0 && !tasks[i].arg) {
			error(_("no such task: '%s'"), argv[0]);
			usage_with_options(usagestr, options);
		}
	}

	argc--;
	argv++;
	setup_enlistment_directory(argc, argv, usagestr, options);
	strbuf_release(&buf);

	if (i == 0)
		return register_dir();

	if (i > 0)
		return run_git("maintenance", "run",
			       "--task", tasks[i].task, NULL);

	if (register_dir())
		return -1;
	for (i = 1; tasks[i].arg; i++)
		if (run_git("maintenance", "run",
			    "--task", tasks[i].task, NULL))
			return -1;
	return 0;
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

	/*
	 * Be forgiving when the enlistment or worktree does not even exist any
	 * longer; This can be the case if a user deleted the worktree by
	 * mistake and _still_ wants to unregister the thing.
	 */
	if (argc == 1) {
		struct strbuf path = STRBUF_INIT;

		strbuf_addf(&path, "%s/src/.git", argv[0]);
		if (!is_directory(path.buf)) {
			int res = 0;

			strbuf_strip_suffix(&path, "/.git");
			strbuf_realpath_forgiving(&path, path.buf, 1);

			if (run_git("config", "--global",
				    "--unset", "--fixed-value",
				    "scalar.repo", path.buf, NULL) < 0)
				res = -1;

			if (run_git("config", "--global",
				    "--unset", "--fixed-value",
				    "maintenance.repo", path.buf, NULL) < 0)
				res = -1;

			strbuf_release(&path);
			return res;
		}
		strbuf_release(&path);
	}

	setup_enlistment_directory(argc, argv, usage, options);

	return unregister_dir();
}

struct {
	const char *name;
	int (*fn)(int, const char **);
} builtins[] = {
	{ "clone", cmd_clone },
	{ "list", cmd_list },
	{ "register", cmd_register },
	{ "unregister", cmd_unregister },
	{ "run", cmd_run },
	{ "reconfigure", cmd_reconfigure },
	{ "diagnose", cmd_diagnose },
	{ NULL, NULL},
};

int cmd_main(int argc, const char **argv)
{
	struct strbuf scalar_usage = STRBUF_INIT;
	int i;

	if (argc > 1) {
		argv++;
		argc--;

		if (!strcmp(argv[0], "config"))
			argv[0] = "reconfigure";

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
