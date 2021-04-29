/*
 * This is a port of Scalar to C.
 */

#include "cache.h"
#include "gettext.h"
#include "parse-options.h"
#include "config.h"
#include "run-command.h"
#include "strbuf.h"
#include "refs.h"
#include "version.h"
#include "dir.h"
#include "json-parser.h"

static int is_unattended(void) {
	return git_env_bool("Scalar_UNATTENDED", 0);
}

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

static void ensure_absolute_path(char **p)
{
	char *absolute;

	if (is_absolute_path(*p))
		return;

	absolute = real_pathdup(*p, 1);
	free(*p);
	*p = absolute;
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

/* printf-style interface, expects `<key>=<value>` argument */
static int set_config(const char *file, const char *fmt, ...)
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
	res = git_config_set_in_file_gently(file, buf.buf, value);
	strbuf_release(&buf);

	return res;
}

/* Find N for which .CacheServers[N].GlobalDefault == true */
static int get_cache_server_index(struct json_iterator *it)
{
	const char *p;
	char *q;
	long l;

	if (it->type == JSON_TRUE &&
	    skip_iprefix(it->key.buf, ".CacheServers[", &p) &&
	    (l = strtol(p, &q, 10)) >= 0 && p != q &&
	    !strcasecmp(q, "].GlobalDefault")) {
		*(long *)it->fn_data = l;
		return 1;
	}

	return 0;
}

struct cache_server_url_data {
	char *key, *url;
};

/* Get .CacheServers[N].Url */
static int get_cache_server_url(struct json_iterator *it)
{
	struct cache_server_url_data *data = it->fn_data;

	if (it->type == JSON_STRING &&
	    !strcasecmp(data->key, it->key.buf)) {
		data->url = strbuf_detach(&it->string_value, NULL);
		return 1;
	}

	return 0;
}

static int can_url_support_gvfs(const char *url)
{
	return starts_with(url, "https://") ||
		(git_env_bool("GIT_TEST_ALLOW_GVFS_VIA_HTTP", 0) &&
		 starts_with(url, "http://"));
}

/*
 * If `cache_server_url` is `NULL`, print the list to `stdout`.
 */
static int supports_gvfs_protocol(const char *dir, const char *url,
				  char **cache_server_url)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf out = STRBUF_INIT;

	/*
	 * The GVFS protocol is only supported via https://; For testing, we
	 * also allow http://.
	 */
	if (!can_url_support_gvfs(url))
		return 0;

	cp.git_cmd = 1;
	cp.dir = dir; /* gvfs-helper requires a Git repository */
	strvec_pushl(&cp.args, "gvfs-helper", "--remote", url, "config", NULL);
	if (!pipe_command(&cp, NULL, 0, &out, 512, NULL, 0)) {
		long l = 0;
		struct json_iterator it =
			JSON_ITERATOR_INIT(out.buf, get_cache_server_index, &l);
		struct cache_server_url_data data = { .url = NULL };

		if (iterate_json(&it) < 0) {
			strbuf_release(&out);
			return error("JSON parse error");
		}
		data.key = xstrfmt(".CacheServers[%ld].Url", l);
		it.fn = get_cache_server_url;
		it.fn_data = &data;
		if (iterate_json(&it) < 0) {
			strbuf_release(&out);
			return error("JSON parse error");
		}
		*cache_server_url = data.url;
		free(data.key);
		return 1;
	}
	strbuf_release(&out);
	return 0; /* error out quietly */
}

static int cmd_cache_server(int argc, const char **argv)
{
	enum {
		GET, SET, LIST
	} mode = GET;
	struct option cache_server_options[] = {
		OPT_CMDMODE(0, "get", &mode,
			    N_("get the configured cache-server URL"), GET),
		OPT_CMDMODE(0, "set", &mode,
			    N_("set the configured cache-server URL"), SET),
		OPT_CMDMODE(0, "list", &mode,
			    N_("list the possible cache-server URLs"), LIST),
		OPT_END(),
	};
	const char * const cache_server_usage[] = {
		N_("git cache_server "
		   "[--get | --set <url> | --list [<remote>]]"),
		NULL
	};

	argc = parse_options(argc, argv, NULL, cache_server_options,
			     cache_server_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);


	if (mode == LIST) {
		if (argc > 1)
			usage_with_options(cache_server_usage,
					   cache_server_options);
		return !!supports_gvfs_protocol(NULL, argc > 0 ?
						argv[0] : "origin", NULL);
	} else if (mode == SET) {
		if (argc != 1)
			usage_with_options(cache_server_usage,
					   cache_server_options);
		return !!set_config(NULL, "gvfs.cache-server=%s", argv[0]);
	} else {
		char *url = NULL;

		if (argc != 0)
			usage_with_options(cache_server_usage,
					   cache_server_options);

		printf("Using cache server: %s\n",
		       git_config_get_string("gvfs.cache-server", &url) ?
		       "(undefined)" : url);
		free(url);
	}

	return 0;
}

static char *default_cache_root(const char *root)
{
	const char *env;

	if (is_unattended())
		return xstrfmt("%s/.scalarCache", root);

#ifdef WIN32
	(void)env;
	return xstrfmt("%.*s.scalarCache", offset_1st_component(root), root);
#elif defined(__APPLE__)
	if ((env = getenv("HOME")) && *env)
		return xstrfmt("%s/.scalarCache", env);
	return NULL;
#else
	if ((env = getenv("XDG_CACHE_HOME")) && *env)
		return xstrfmt("%s/scalar", env);
	if ((env = getenv("HOME")) && *env)
		return xstrfmt("%s/.cache/scalar", env);
	return NULL;
#endif
}

static int get_repository_id(struct json_iterator *it)
{
	if (it->type == JSON_STRING &&
	    !strcasecmp(".repository.id", it->key.buf)) {
		*(char **)it->fn_data = strbuf_detach(&it->string_value, NULL);
		return 1;
	}

	return 0;
}

static char *get_cache_key(const char *dir, const char *url)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf out = STRBUF_INIT;
	char *cache_key = NULL;

	/*
	 * The GVFS protocol is only supported via https://; For testing, we
	 * also allow http://.
	 */
	if (can_url_support_gvfs(url)) {
		cp.git_cmd = 1;
		cp.dir = dir; /* gvfs-helper requires a Git repository */
		strvec_pushl(&cp.args, "gvfs-helper", "--remote", url,
			     "endpoint", "vsts/info", NULL);
		if (!pipe_command(&cp, NULL, 0, &out, 512, NULL, 0)) {
			char *id = NULL;
			struct json_iterator it =
				JSON_ITERATOR_INIT(out.buf, get_repository_id,
						   &id);

			if (iterate_json(&it) < 0)
				warning("JSON parse error (%s)", out.buf);
			else if (id)
				cache_key = xstrfmt("id_%s", id);
			free(id);
		}
	}

	if (!cache_key) {
		struct strbuf downcased = STRBUF_INIT;
		int hash_algo_index = hash_algo_by_name("sha1");
		const struct git_hash_algo *hash_algo = hash_algo_index < 0 ?
			the_hash_algo : &hash_algos[hash_algo_index];
		git_hash_ctx ctx;
		unsigned char hash[GIT_MAX_RAWSZ];

		strbuf_addstr(&downcased, url);
		strbuf_tolower(&downcased);

		hash_algo->init_fn(&ctx);
		hash_algo->update_fn(&ctx, downcased.buf, downcased.len);
		hash_algo->final_fn(hash, &ctx);

		cache_key = xstrfmt("url_%s", hash_to_hex(hash));
	}

	strbuf_release(&out);
	return cache_key;
}

static char *remote_default_branch(const char *dir, const char *url)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf out = STRBUF_INIT;

	cp.git_cmd = 1;
	cp.dir = dir;
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
	cp.dir = dir;
	strvec_pushl(&cp.args, "symbolic-ref", "--short", "HEAD", NULL);
	if (!pipe_command(&cp, NULL, 0, &out, 0, NULL, 0)) {
		strbuf_trim(&out);
		return strbuf_detach(&out, NULL);
	}

	strbuf_release(&out);
	error(_("failed to get default branch name"));
	return NULL;
}

static int set_acls(const char *root)
{
#ifdef WIN32
	// The following permissions are typically present on deskop and missing on Server
	//
	//   ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\Authenticated Users
	//          [OBJECT_INHERIT_ACE]
	//          [CONTAINER_INHERIT_ACE]
	//          [INHERIT_ONLY_ACE]
	//        DELETE
	//        GENERIC_EXECUTE
	//        GENERIC_WRITE
	//        GENERIC_READ
	/* TODO:
	DirectorySecurity rootSecurity = DirectoryEx.GetAccessControl(enlistmentPath);
	AccessRule authenticatedUsersAccessRule = rootSecurity.AccessRuleFactory(
	new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
	unchecked((int)(NativeMethods.FileAccess.DELETE | NativeMethods.FileAccess.GENERIC_EXECUTE | NativeMethods.FileAccess.GENERIC_WRITE | NativeMethods.FileAccess.GENERIC_READ)),
	true,
	InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
	PropagationFlags.None,
	AccessControlType.Allow);

	// The return type of the AccessRuleFactory method is the base class, AccessRule, but the return value can be cast safely to the derived class.
	// https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemsecurity.accessrulefactory(v=vs.110).aspx
	rootSecurity.AddAccessRule((FileSystemAccessRule)authenticatedUsersAccessRule);
	DirectoryEx.SetAccessControl(enlistmentPath, rootSecurity);
	*/
#endif
	return 0;
}

/* TODO: order the non-`cmd_*()` functions before the `cmd_*()` functions */
static int run_config_task(const char *dir);

static int cmd_clone(int argc, const char **argv)
{
	char *cache_server_url = NULL, *branch = NULL;
	int single_branch = 0, no_fetch_commits_and_trees = 0;
	char *local_cache_root = NULL;
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
		OPT_STRING(0, "local-cache-path", &local_cache_root,
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
	char *root = NULL, *dir = NULL, *config_path = NULL;
	char *cache_key = NULL, *shared_cache_path = NULL;
	struct strbuf buf = STRBUF_INIT;
	int res;

	argc = parse_options(argc, argv, NULL, clone_options, clone_usage,
			     PARSE_OPT_KEEP_DASHDASH |
			     PARSE_OPT_STOP_AT_NON_OPTION);

	if (argc == 2) {
		url = argv[0];
		root = xstrdup(argv[1]);
	} else if (argc == 1) {
		url = argv[0];

		strbuf_addstr(&buf, url);
		/* Strip trailing slashes, if any */
		while (buf.len > 0 && is_dir_sep(buf.buf[buf.len - 1]))
			strbuf_setlen(&buf, buf.len - 1);
		/* Strip suffix `.git`, if any */
		strbuf_strip_suffix(&buf, ".git");

		root = find_last_dir_sep(buf.buf);
		if (!root) {
			die(_("cannot deduce worktree name from '%s'"), url);
		}
		root = xstrdup(root + 1);
	} else {
		usage_msg_opt(N_("need a URL"), clone_usage, clone_options);
	}

	ensure_absolute_path(&root);

	dir = xstrfmt("%s/src", root);

	if (!local_cache_root)
		local_cache_root = default_cache_root(root);
	else
		ensure_absolute_path(&local_cache_root);

	if (!local_cache_root)
		die(_("could not determine local cache root"));

	if (dir_inside_of(local_cache_root, dir) >= 0)
		die(_("'--local-cache-path' cannot be inside the src folder"));


	/* TODO: CheckNotInsideExistingRepo */

	if (is_non_empty_dir(dir)) {
		die(_("'%s' exists and is not empty"), dir);
	}

	strbuf_reset(&buf);
	if (branch)
		strbuf_addf(&buf, "init.defaultBranch=%s", branch);
	else {
		char *b = repo_default_branch_name(the_repository, 1);
		strbuf_addf(&buf, "init.defaultBranch=%s", b);
		free(b);
	}

	if ((res = run_git(NULL, "-c", buf.buf, "init", "--", dir, NULL)))
		goto cleanup;

	/* TODO: trace command-line options, is_unattended, elevated, dir */
	trace2_data_intmax("scalar", the_repository, "unattended",
			   is_unattended());

	/*
	 * TODO: verify that the file system is case-insensitive on Windows and
	 * macOS, and case-sensitive on Linux.
	 */

	if ((res = set_acls(dir)) < 0)
		goto cleanup;

	if (!branch &&
	    !(branch = remote_default_branch(dir, url))) {
		res = error(_("failed to get default branch for '%s'"), url);
		goto cleanup;
	}

	config_path = xstrfmt("%s/.git/config", dir);

	if (!(cache_key = get_cache_key(dir, url))) {
		res = error(_("could not determine cache key for '%s'"), url);
		goto cleanup;
	}

	shared_cache_path = xstrfmt("%s/%s", local_cache_root, cache_key);
	if (set_config(config_path, "gvfs.sharedCache=%s", shared_cache_path)) {
		res = error(_("could not configure shared cache"));
		goto cleanup;
	}

	strbuf_reset(&buf);
	strbuf_addf(&buf, "%s/pack", shared_cache_path);
	switch (safe_create_leading_directories(buf.buf)) {
	case SCLD_OK: case SCLD_EXISTS:
		break; /* okay */
	default:
		res = error_errno(_("could not initialize '%s'"), buf.buf);
		goto cleanup;
	}

	if (set_config(config_path, "remote.origin.url=%s", url) ||
	    set_config(config_path, "remote.origin.fetch="
		    "+refs/heads/%s:refs/remotes/origin/%s",
		    single_branch ? branch : "*",
		    single_branch ? branch : "*")) {
		res = error(_("could not configure remote in '%s'"), dir);
		goto cleanup;
	}

	if (cache_server_url ||
	    supports_gvfs_protocol(dir, url, &cache_server_url)) {
		if (set_config(config_path, "core.useGVFSHelper=true") ||
		    set_config(config_path, "core.gvfs=150")) {
			res = error(_("could not turn on GVFS helper"));
			goto cleanup;
		}
		if (cache_server_url &&
		    set_config(config_path,
			       "gvfs.cache-server=%s", cache_server_url)) {
			res = error(_("could not configure cache server"));
			goto cleanup;
		}
	} else {
		if (set_config(config_path, "core.useGVFSHelper=false") ||
		    set_config(config_path, "remote.origin.promisor=true") ||
		    set_config(config_path,
			       "remote.origin.partialCloneFilter=blob:none")) {
			res = error(_("could not configure partial clone in "
				      "'%s'"), dir);
			goto cleanup;
		}
	}

	if (!full_clone &&
	    (res = run_git(dir, "sparse-checkout", "init", "--cone", NULL)))
		goto cleanup;

	if (set_recommended_config(config_path))
		return error(_("could not configure '%s'"), dir);

	/*
	 * TODO: should we pipe the output and grep for "filtering not
	 * recognized by server", and suppress the error output in
	 * that case?
	 */
	if ((res = run_git(dir, "fetch", "--quiet", "origin", NULL))) {
		warning(_("Partial clone failed; Trying full clone"));

		if (set_config(config_path, "remote.origin.promisor") ||
		    set_config(config_path,
			       "remote.origin.partialCloneFilter")) {
			res = error(_("could not configure for full clone"));
			goto cleanup;
		}

		if ((res = run_git(dir, "fetch", "--quiet", "origin", NULL)))
			goto cleanup;
	}

	if ((res = set_config(config_path, "branch.%s.remote=origin", branch)))
		goto cleanup;
	if ((res = set_config(config_path, "branch.%s.merge=refs/heads/%s",
			      branch, branch)))
		goto cleanup;

	strbuf_reset(&buf);
	strbuf_addf(&buf, "origin/%s", branch);
	res = run_git(dir, "checkout", "-f", "-t", buf.buf, NULL);
	if (res)
		goto cleanup;

	res = run_config_task(dir);

cleanup:
	free(root);
	free(dir);
	free(config_path);
	strbuf_release(&buf);
	free(branch);
	free(cache_server_url);
	free(local_cache_root);
	free(cache_key);
	free(shared_cache_path);
	return res;
}

static void spinner(void)
{
	static const char whee[] = "|\010/\010-\010\\\010", *next = whee;

	if (!next)
		return;
	if (write(2, next, 2) < 0)
		next = NULL;
	else
		next = next[2] ? next + 2 : whee;
}

static int stage(const char *git_dir, struct strbuf *buf, const char *path)
{
	struct strbuf cacheinfo = STRBUF_INIT;
	struct child_process cp = CHILD_PROCESS_INIT;
	int res;

	spinner();

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

static int cmd_diagnose(int argc, const char **argv)
{
	struct strbuf tmp_dir = STRBUF_INIT;
	time_t now = time(NULL);
	struct tm tm;
	struct strbuf path = STRBUF_INIT, buf = STRBUF_INIT;
	int res = 0;

	if (argc != 1)
		die("'scalar diagnose' does not accept any arguments");

	strbuf_addstr(&buf, "../.scalarDiagnostics/scalar_");
	strbuf_addftime(&buf, "%Y%m%d_%H%M%S",
			localtime_r(&now, &tm), 0, 0);
	if (run_git(NULL, "init", "-q", "-b", "dummy",
		    "--bare", buf.buf, NULL)) {
		res = error(_("could not initialize temporary repository: %s"),
			    buf.buf);
		goto diagnose_cleanup;
	}
	strbuf_realpath(&tmp_dir, buf.buf, 1);

	strbuf_reset(&buf);
	strbuf_addf(&buf, "Collecting diagnostic info into temp folder %s\n\n",
		    tmp_dir.buf);

	strbuf_addf(&buf, "git version %s\n", git_version_string);
	strbuf_addf(&buf, "built from commit: %s\n\n",
		    git_built_from_commit_string[0] ?
		    git_built_from_commit_string : "(n/a)");

	strbuf_addf(&buf, "Enlistment root: %s\n", the_repository->worktree);
	strbuf_addf(&buf,
		    "Cache Server: None\n"
		    "Local Cache:\n"
		    "\n");
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

	/*
	 * TODO: add more stuff:
	 * disk space info
	 * LogDirectoryEnumeration(...DotGit.Objects.Root), ScalarConstants.DotGit.Objects.Pack.Root, "packs-local.txt");
	 * LogLooseObjectCount(...DotGit.Objects.Root), ScalarConstants.DotGit.Objects.Root, "objects-local.txt");
	 *
	 * CopyLocalCacheData(archiveFolderPath, gitObjectsRoot);
	 */

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
	return run_git(NULL, "config", "--get-all", "scalar.repo", NULL);
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

	res = run_git(NULL, "config", "--global", "--get",
		      "--fixed-value", "scalar.repo", worktree, NULL);

	/*
	 * If we want to add and the setting is already there, then do nothing.
	 * If we want to remove and the setting is not there, then do nothing.
	 */
	if ((add && !res) || (!add && res))
		res = 0;
	else
		res = run_git(NULL, "config", "--global",
			      add ? "--add" : "--unset",
			      add ? "--no-fixed-value" : "--fixed-value",
			      "scalar.repo", worktree, NULL);

	free(p);
	return res;
}

static int stop_fsmonitor_daemon(const char *dir)
{
#ifndef HAVE_FSMONITOR_DAEMON_BACKEND
	return 0;
#else
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf err = STRBUF_INIT;
	int res;

	cp.dir = dir;
	cp.git_cmd = 1;
	strvec_pushl(&cp.args, "fsmonitor--daemon", "--stop", NULL);
	strvec_push(&cp.env_array, "LC_ALL=C");
	res = pipe_command(&cp, NULL, 0, NULL, 0, &err, 0);

	if (res == 128 &&
	    !strcmp("fatal: fsmonitor--daemon is not running", err.buf))
		res = 0;
	else if (res)
		fwrite(err.buf, err.len, 1, stderr);

	strbuf_release(&err);
	return res;
#endif
}

static int toggle_maintenance(const char *dir, int enable)
{
	/*
	 * TODO: check whether the Scalar service used to run `scalar run` and
	 * if so, whether it ran the config step. In the positive case, we will
	 * have to extend `git maintenance` to allow for user-defined tasks,
	 * and register one.
	 */
	return run_git(dir, "maintenance", enable ? "start" : "unregister",
		       NULL);
}

static int run_config_task(const char *dir)
{
	char *config = dir ? xstrfmt("%s/.git/config", dir) : NULL;
	int res = 0;

	/* TODO: turn `feature.scalar` into the appropriate settings */
	/* TODO: enable FSMonitor and other forgotten settings */

	res = res || add_or_remove_enlistment(dir, 1);
	res = res || set_recommended_config(config);
	res = res || toggle_maintenance(dir, 1);

	free(config);
	return res;
}

static int cmd_register(int argc, const char **argv)
{
	return run_config_task(NULL);
}

static const char scalar_run_usage[] =
	N_("scalar run <task>\n"
	   "\ttasks: all, config, commit-graph,\n"
	   "\t       fetch, loose-objects, pack-files");

static struct {
	const char *arg, *task;
} tasks[] = {
	{ "config", NULL },
	{ "commit-graph", "commit-graph" },
	{ "fetch", "prefetch" },
	{ "loose-objects", "loose-objects" },
	{ "pack-files", "incremental-repack" },
	{ NULL, NULL }
};

static int run_maintenance_task(const char *arg)
{
	int i;

	if (!strcmp("config", arg))
		return run_config_task(NULL);
	else if (!strcmp("all", arg)) {
		for (i = 0; tasks[i].arg; i++)
			if (run_maintenance_task(tasks[i].arg))
				return -1;
		return 0;
	}

	for (i = 0; tasks[i].arg; i++)
		if (!strcmp(tasks[i].arg, arg))
			return run_git(NULL, "maintenance", "run", "--task",
				       tasks[i].task, NULL);

	return error(_("no such task: '%s'"), arg);
}

static int cmd_run(int argc, const char **argv)
{
	if (argc != 2)
		usage(scalar_run_usage);

	return run_maintenance_task(argv[1]);
}

static int cmd_unregister(int argc, const char **argv)
{
	int res = 0;

	res = res || stop_fsmonitor_daemon(NULL);
	res = res || toggle_maintenance(NULL, 0);
	res = res || add_or_remove_enlistment(NULL, 0);
	return res;
}

static int cmd_test(int argc, const char **argv)
{
	const char *url = argc > 1 ?
		argv[1] : "https://gvfs@dev.azure.com/gvfs/ci/_git/ForTests";
	char *cache_key = get_cache_key(NULL, url);

	printf("key: %s\n", cache_key);

	return 0;
}

struct {
	const char *name;
	int (*fn)(int, const char **);
	int needs_git_repo;
} builtins[] = {
	{ "cache-server", cmd_cache_server, 1 },
	{ "clone", cmd_clone, 0 },
	{ "diagnose", cmd_diagnose, 1 },
	{ "list", cmd_list, 0 },
	{ "register", cmd_register, 1 },
	{ "run", cmd_run, 1 },
	{ "unregister", cmd_unregister, 1 },
	{ "test", cmd_test, 0 },
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
