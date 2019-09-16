#include "builtin.h"
#include "config.h"
#include "dir.h"
#include "parse-options.h"
#include "pathspec.h"
#include "repository.h"
#include "run-command.h"
#include "strbuf.h"
#include "string-list.h"

static char const * const builtin_sparse_checkout_usage[] = {
	N_("git sparse-checkout [init|add|list|disable]"),
	NULL
};

static const char * const builtin_sparse_checkout_init_usage[] = {
	N_("git sparse-checkout init [--cone]"),
	NULL
};

struct opts_sparse_checkout {
	const char *subcommand;
	int read_stdin;
	int cone;
} opts;

static char *get_sparse_checkout_filename(void)
{
	return git_pathdup("info/sparse-checkout");
}

static void write_excludes_to_file(FILE *fp, struct exclude_list *el)
{
	int i;

	for (i = 0; i < el->nr; i++) {
		struct exclude *x = el->excludes[i];

		if (x->flags & EXC_FLAG_NEGATIVE)
			fprintf(fp, "!");

		fprintf(fp, "%s", x->pattern);

		if (x->flags & EXC_FLAG_MUSTBEDIR)
			fprintf(fp, "/");

		fprintf(fp, "\n");
	}
}

static void write_cone_to_file(FILE *fp, struct exclude_list *el)
{
	int i;
	struct exclude_entry *entry;
	struct hashmap_iter iter;
	struct string_list sl = STRING_LIST_INIT_DUP;

	hashmap_iter_init(&el->parent_hashmap, &iter);
	while ((entry = hashmap_iter_next(&iter))) {
		char *pattern = xstrdup(entry->pattern);
		char *converted = pattern;
		if (pattern[0] == '/')
			converted++;
		if (pattern[entry->patternlen - 1] == '/')
			pattern[entry->patternlen - 1] = 0;
		string_list_insert(&sl, converted);
		free(pattern);
	}

	string_list_sort(&sl);
	string_list_remove_duplicates(&sl, 0);

	for (i = 0; i < sl.nr; i++) {
		char *pattern = sl.items[i].string;

		if (!strcmp(pattern, ""))
			fprintf(fp, "/*\n!/*/*\n");
		else
			fprintf(fp, "/%s/*\n!/%s/*/*\n", pattern, pattern);
	}

	string_list_clear(&sl, 0);

	hashmap_iter_init(&el->recursive_hashmap, &iter);
	while ((entry = hashmap_iter_next(&iter))) {
		char *pattern = xstrdup(entry->pattern);
		char *converted = pattern;
		if (pattern[0] == '/')
			converted++;
		if (pattern[entry->patternlen - 1] == '/')
			pattern[entry->patternlen - 1] = 0;
		string_list_insert(&sl, converted);
		free(pattern);
	}

	string_list_sort(&sl);
	string_list_remove_duplicates(&sl, 0);

	for (i = 0; i < sl.nr; i++) {
		char *pattern = sl.items[i].string;
		fprintf(fp, "/%s/*\n", pattern);
	}
}

static int sparse_checkout_list(int argc, const char **argv)
{
	struct exclude_list el;
	char *sparse_filename;
	int res;

	memset(&el, 0, sizeof(el));

	sparse_filename = get_sparse_checkout_filename();
	res = add_excludes_from_file_to_list(sparse_filename, "", 0, &el, NULL);
	free(sparse_filename);

	if (res < 0) {
		warning(_("failed to parse sparse-checkout file; it may not exist"));
		return 0;
	}

	write_excludes_to_file(stdout, &el);
	clear_exclude_list(&el);

	return 0;
}

static int sc_read_tree(void)
{
	struct argv_array argv = ARGV_ARRAY_INIT;
	int result = 0;
	argv_array_pushl(&argv, "read-tree", "-m", "-u", "HEAD", NULL);

	if (run_command_v_opt(argv.argv, RUN_GIT_CMD)) {
		error(_("failed to update index with new sparse-checkout paths"));
		result = 1;
	}

	argv_array_clear(&argv);
	return result;
}

static int sc_set_config(enum sparse_checkout_mode mode)
{
	struct argv_array argv = ARGV_ARRAY_INIT;
	int result = 0;
	argv_array_pushl(&argv, "config", "--add", "core.sparseCheckout", NULL);

	switch (mode) {
	case SPARSE_CHECKOUT_FULL:
		argv_array_pushl(&argv, "true", NULL);
		break;

	case SPARSE_CHECKOUT_CONE:
		argv_array_pushl(&argv, "cone", NULL);
		break;

	case SPARSE_CHECKOUT_NONE:
		argv_array_pushl(&argv, "false", NULL);
		break;

	default:
		die(_("invalid config mode"));
	}

	if (run_command_v_opt(argv.argv, RUN_GIT_CMD)) {
		error(_("failed to enable core.sparseCheckout"));
		result = 1;
	}

	argv_array_clear(&argv);
	return result;
}

static int delete_directory(const struct object_id *oid, struct strbuf *base,
		const char *pathname, unsigned mode, int stage, void *context)
{
	struct strbuf dirname = STRBUF_INIT;
	struct stat sb;

	strbuf_addstr(&dirname, the_repository->worktree);
	strbuf_addch(&dirname, '/');
	strbuf_addstr(&dirname, pathname);

	if (stat(dirname.buf, &sb) || !(sb.st_mode & S_IFDIR))
		return 0;

	if (remove_dir_recursively(&dirname, 0))
		warning(_("failed to remove directory '%s'"),
			dirname.buf);

	strbuf_release(&dirname);
	return 0;
}

static int sparse_checkout_init(int argc, const char **argv)
{
	struct tree *t;
	struct object_id oid;
	struct exclude_list el;
	static struct pathspec pathspec;
	char *sparse_filename;
	FILE *fp;
	int res;
	enum sparse_checkout_mode mode;

	static struct option builtin_sparse_checkout_init_options[] = {
		OPT_BOOL(0, "cone", &opts.cone,
			 N_("initialize the sparse-checkout in cone mode")),
		OPT_END(),
	};

	argc = parse_options(argc, argv, NULL,
			     builtin_sparse_checkout_init_options,
			     builtin_sparse_checkout_init_usage, 0);

	mode = opts.cone ? SPARSE_CHECKOUT_CONE : SPARSE_CHECKOUT_FULL;

	if (sc_set_config(mode))
		return 1;

	memset(&el, 0, sizeof(el));

	sparse_filename = get_sparse_checkout_filename();
	res = add_excludes_from_file_to_list(sparse_filename, "", 0, &el, NULL);

	/* If we already have a sparse-checkout file, use it. */
	if (res >= 0) {
		free(sparse_filename);
		goto reset_dir;
	}

	/* initial mode: all blobs at root */
	fp = fopen(sparse_filename, "w");
	free(sparse_filename);
	fprintf(fp, "/*\n!/*/*\n");
	fclose(fp);

	/* remove all directories in the root, if tracked by Git */
	if (get_oid("HEAD", &oid)) {
		/* assume we are in a fresh repo */
		return 0;
	}

	t = parse_tree_indirect(&oid);

	parse_pathspec(&pathspec, PATHSPEC_ALL_MAGIC &
				  ~(PATHSPEC_FROMTOP | PATHSPEC_LITERAL),
		       PATHSPEC_PREFER_CWD,
		       "", NULL);

	if (read_tree_recursive(the_repository, t, "", 0, 0, &pathspec,
				delete_directory, NULL))
		return 1;

reset_dir:
	return sc_read_tree();
}

static void insert_recursive_pattern(struct exclude_list *el, struct strbuf *path)
{
	struct exclude_entry *e = xmalloc(sizeof(struct exclude_entry));
	e->patternlen = path->len;
	e->pattern = strbuf_detach(path, NULL);
	hashmap_entry_init(e, memhash(e->pattern, e->patternlen));

	hashmap_add(&el->recursive_hashmap, e);

	while (e->patternlen) {
		char *slash = strrchr(e->pattern, '/');
		char *oldpattern = e->pattern;
		size_t newlen;

		if (!slash)
			break;

		newlen = slash - e->pattern;
		e = xmalloc(sizeof(struct exclude_entry));
		e->patternlen = newlen;
		e->pattern = xstrndup(oldpattern, newlen);
		hashmap_entry_init(e, memhash(e->pattern, e->patternlen));

		if (!hashmap_get(&el->parent_hashmap, e, NULL))
			hashmap_add(&el->parent_hashmap, e);
	}
}

static int sparse_checkout_add(int argc, const char **argv)
{
	struct exclude_list el;
	char *sparse_filename;
	FILE *fp;
	struct strbuf line = STRBUF_INIT;

	memset(&el, 0, sizeof(el));

	sparse_filename = get_sparse_checkout_filename();
	add_excludes_from_file_to_list(sparse_filename, "", 0, &el, NULL);

	fp = fopen(sparse_filename, "w");

	if (core_sparse_checkout == SPARSE_CHECKOUT_FULL) {
		write_excludes_to_file(fp, &el);

		while (!strbuf_getline(&line, stdin)) {
			strbuf_trim(&line);
			fprintf(fp, "%s\n", line.buf);
		}
	} else if (core_sparse_checkout == SPARSE_CHECKOUT_CONE) {
		while (!strbuf_getline(&line, stdin)) {
			strbuf_trim(&line);

			strbuf_trim_trailing_dir_sep(&line);

			if (!line.len)
				continue;

			if (line.buf[0] == '/')
				strbuf_remove(&line, 0, 1);

			if (!line.len)
				continue;

			insert_recursive_pattern(&el, &line);
		}

		write_cone_to_file(fp, &el);
	}

	fclose(fp);
	free(sparse_filename);

	clear_exclude_list(&el);

	return sc_read_tree();
}

static int sparse_checkout_disable(int argc, const char **argv)
{
	char *sparse_filename;
	FILE *fp;

	if (sc_set_config(SPARSE_CHECKOUT_FULL))
		die(_("failed to change config"));

	sparse_filename = get_sparse_checkout_filename();
	fp = fopen(sparse_filename, "w");
	fprintf(fp, "/*\n");
	fclose(fp);

	if (sc_read_tree())
		die(_("error while refreshing working directory"));

	unlink(sparse_filename);
	free(sparse_filename);

	return sc_set_config(SPARSE_CHECKOUT_NONE);
}

int cmd_sparse_checkout(int argc, const char **argv, const char *prefix)
{
	static struct option builtin_sparse_checkout_options[] = {
		OPT_END(),
	};

	if (argc == 2 && !strcmp(argv[1], "-h"))
		usage_with_options(builtin_sparse_checkout_usage,
				   builtin_sparse_checkout_options);

	git_config(git_default_config, NULL);
	argc = parse_options(argc, argv, prefix,
			     builtin_sparse_checkout_options,
			     builtin_sparse_checkout_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);

	if (argc > 0) {
		if (!strcmp(argv[0], "list"))
			return sparse_checkout_list(argc, argv);
		if (!strcmp(argv[0], "init"))
			return sparse_checkout_init(argc, argv);
		if (!strcmp(argv[0], "add"))
			return sparse_checkout_add(argc, argv);
		if (!strcmp(argv[0], "disable"))
			return sparse_checkout_disable(argc, argv);
	}

	usage_with_options(builtin_sparse_checkout_usage,
			   builtin_sparse_checkout_options);
}
