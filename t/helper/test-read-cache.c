#define USE_THE_REPOSITORY_VARIABLE

#include "test-tool.h"
#include "config.h"
#include "environment.h"
#include "name-hash.h"
#include "read-cache-ll.h"
#include "repository.h"
#include "setup.h"
#include "sparse-index.h"

/*
 * Look up 'name' in the name-hash, expand the index to a full index, and
 * look it up again. The first lookup initializes the name-hash.
 */
static void expand_and_find(struct index_state *istate, const char *name)
{
	int before = !!index_file_exists(istate, name, strlen(name), 0);

	ensure_full_index(istate);
	printf("%s: %s, %s\n", name,
	       before ? "found" : "not found",
	       index_file_exists(istate, name, strlen(name), 0) ?
	       "found" : "not found");
}

int cmd__read_cache(int argc, const char **argv)
{
	int i, cnt = 1;
	const char *name = NULL;
	const char *find_name = NULL;

	if (argc > 1 && skip_prefix(argv[1], "--print-and-refresh=", &name)) {
		argc--;
		argv++;
	}

	if (argc > 1 &&
	    skip_prefix(argv[1], "--expand-and-find=", &find_name)) {
		argc--;
		argv++;
	}

	if (argc == 2)
		cnt = strtol(argv[1], NULL, 0);
	setup_git_directory(the_repository);
	repo_config(the_repository, git_default_config, NULL);

	if (find_name) {
		/* Read the index as it is on disk, without an expansion. */
		prepare_repo_settings(the_repository);
		the_repository->settings.command_requires_full_index = 0;
	}

	for (i = 0; i < cnt; i++) {
		repo_read_index(the_repository);
		if (find_name)
			expand_and_find(the_repository->index, find_name);
		if (name) {
			int pos;

			refresh_index(the_repository->index, REFRESH_QUIET,
				      NULL, NULL, NULL);
			pos = index_name_pos(the_repository->index, name, strlen(name));
			if (pos < 0)
				die("%s not in index", name);
			printf("%s is%s up to date\n", name,
			       ce_uptodate(the_repository->index->cache[pos]) ? "" : " not");
			write_file(name, "%d\n", i);
		}
		discard_index(the_repository->index);
	}
	return 0;
}
