#include "builtin.h"
#include "config.h"
#include "environment.h"
#include "hex.h"
#include "json-writer.h"
#include "list-objects.h"
#include "object-name.h"
#include "object-store.h"
#include "parse-options.h"
#include "progress.h"
#include "ref-filter.h"
#include "refs.h"
#include "revision.h"
#include "run-command.h"
#include "strbuf.h"
#include "strmap.h"
#include "strvec.h"
#include "trace2.h"
#include "tree.h"
#include "tree-walk.h"

static const char * const survey_usage[] = {
	N_("(EXPERIMENTAL!) git survey <options>"),
	NULL,
};

static struct progress *survey_progress = NULL;
static uint64_t survey_progress_total = 0;

struct survey_refs_wanted {
	int want_all_refs; /* special override */

	int want_branches;
	int want_tags;
	int want_remotes;
	int want_detached;
	int want_other; /* see FILTER_REFS_OTHERS -- refs/notes/, refs/stash/ */
};

static struct strvec survey_vec_refs_wanted = STRVEC_INIT;

/*
 * The set of refs that we will search if the user doesn't select
 * any on the command line.
 */
static struct survey_refs_wanted refs_if_unspecified = {
	.want_all_refs = 0,

	.want_branches = 1,
	.want_tags = 1,
	.want_remotes = 1,
	.want_detached = 0,
	.want_other = 0,
};

struct survey_opts {
	int verbose;
	int show_progress;
	int show_json;

	int show_largest_commits_by_nr_parents;
	int show_largest_commits_by_size_bytes;

	int show_largest_trees_by_nr_entries;
	int show_largest_trees_by_size_bytes;

	int show_largest_blobs_by_size_bytes;

	struct survey_refs_wanted refs;
};

#define DEFAULT_SHOW_LARGEST_VALUE (10)

static struct survey_opts survey_opts = {
	.verbose = 0,
	.show_progress = -1, /* defaults to isatty(2) */
	.show_json = 0, /* defaults to pretty */

	/*
	 * Show the largest `n` objects for some scaling dimension.
	 * We allow each to be requested independently.
	 */
	.show_largest_commits_by_nr_parents = DEFAULT_SHOW_LARGEST_VALUE,
	.show_largest_commits_by_size_bytes = DEFAULT_SHOW_LARGEST_VALUE,

	.show_largest_trees_by_nr_entries = DEFAULT_SHOW_LARGEST_VALUE,
	.show_largest_trees_by_size_bytes = DEFAULT_SHOW_LARGEST_VALUE,

	.show_largest_blobs_by_size_bytes = DEFAULT_SHOW_LARGEST_VALUE,

	.refs.want_all_refs = 0,

	.refs.want_branches = -1, /* default these to undefined */
	.refs.want_tags = -1,
	.refs.want_remotes = -1,
	.refs.want_detached = -1,
	.refs.want_other = -1,
};

/*
 * After parsing the command line arguments, figure out which refs we
 * should scan.
 *
 * If ANY were given in positive sense, then we ONLY include them and
 * do not use the builtin values.
 */
static void fixup_refs_wanted(void)
{
	struct survey_refs_wanted *rw = &survey_opts.refs;

	/*
	 * `--all-refs` overrides and enables everything.
	 */
	if (rw->want_all_refs == 1) {
		rw->want_branches = 1;
		rw->want_tags = 1;
		rw->want_remotes = 1;
		rw->want_detached = 1;
		rw->want_other = 1;
		return;
	}

	/*
	 * If none of the `--<ref-type>` were given, we assume all
	 * of the builtin unspecified values.
	 */
	if (rw->want_branches == -1 &&
	    rw->want_tags == -1 &&
	    rw->want_remotes == -1 &&
	    rw->want_detached == -1 &&
	    rw->want_other == -1) {
		*rw = refs_if_unspecified;
		return;
	}

	/*
	 * Since we only allow positive boolean values on the command
	 * line, we will only have true values where they specified
	 * a `--<ref-type>`.
	 *
	 * So anything that still has an unspecified value should be
	 * set to false.
	 */
	if (rw->want_branches == -1)
		rw->want_branches = 0;
	if (rw->want_tags == -1)
		rw->want_tags = 0;
	if (rw->want_remotes == -1)
		rw->want_remotes = 0;
	if (rw->want_detached == -1)
		rw->want_detached = 0;
	if (rw->want_other == -1)
		rw->want_other = 0;
}

static struct option survey_options[] = {
	OPT__VERBOSE(&survey_opts.verbose, N_("verbose output")),
	OPT_BOOL(0, "progress", &survey_opts.show_progress, N_("show progress")),
	OPT_BOOL(0, "json",     &survey_opts.show_json, N_("report stats in JSON")),

	OPT_BOOL_F(0, "all-refs", &survey_opts.refs.want_all_refs, N_("include all refs"),          PARSE_OPT_NONEG),

	OPT_BOOL_F(0, "branches", &survey_opts.refs.want_branches, N_("include branches"),          PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "tags",     &survey_opts.refs.want_tags,     N_("include tags"),              PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "remotes",  &survey_opts.refs.want_remotes,  N_("include all remotes refs"),  PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "detached", &survey_opts.refs.want_detached, N_("include detached HEAD"),     PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "other",    &survey_opts.refs.want_other,    N_("include notes and stashes"), PARSE_OPT_NONEG),

	OPT_INTEGER_F(0, "commit-parents", &survey_opts.show_largest_commits_by_nr_parents, N_("show N largest commits by parent count"),  PARSE_OPT_NONEG),
	OPT_INTEGER_F(0, "commit-sizes",   &survey_opts.show_largest_commits_by_size_bytes, N_("show N largest commits by size in bytes"), PARSE_OPT_NONEG),

	OPT_INTEGER_F(0, "tree-entries",   &survey_opts.show_largest_trees_by_nr_entries,   N_("show N largest trees by entry count"),     PARSE_OPT_NONEG),
	OPT_INTEGER_F(0, "tree-sizes",     &survey_opts.show_largest_trees_by_size_bytes,   N_("show N largest trees by size in bytes"),   PARSE_OPT_NONEG),

	OPT_INTEGER_F(0, "blob-sizes",     &survey_opts.show_largest_blobs_by_size_bytes,   N_("show N largest blobs by size in bytes"),   PARSE_OPT_NONEG),

	OPT_END(),
};

static int survey_load_config_cb(const char *var, const char *value,
				 const struct config_context *ctx, void *pvoid)
{
	if (!strcmp(var, "survey.verbose")) {
		survey_opts.verbose = git_config_bool(var, value);
		return 0;
	}
	if (!strcmp(var, "survey.progress")) {
		survey_opts.show_progress = git_config_bool(var, value);
		return 0;
	}
	if (!strcmp(var, "survey.json")) {
		survey_opts.show_json = git_config_bool(var, value);
		return 0;
	}

	if (!strcmp(var, "survey.showcommitparents")) {
		survey_opts.show_largest_commits_by_nr_parents = git_config_ulong(var, value, ctx->kvi);
		return 0;
	}
	if (!strcmp(var, "survey.showcommitsizes")) {
		survey_opts.show_largest_commits_by_size_bytes = git_config_ulong(var, value, ctx->kvi);
		return 0;
	}

	if (!strcmp(var, "survey.showtreeentries")) {
		survey_opts.show_largest_trees_by_nr_entries = git_config_ulong(var, value, ctx->kvi);
		return 0;
	}
	if (!strcmp(var, "survey.showtreesizes")) {
		survey_opts.show_largest_trees_by_size_bytes = git_config_ulong(var, value, ctx->kvi);
		return 0;
	}

	if (!strcmp(var, "survey.showblobsizes")) {
		survey_opts.show_largest_blobs_by_size_bytes = git_config_ulong(var, value, ctx->kvi);
		return 0;
	}

	return git_default_config(var, value, ctx, pvoid);
}

static void survey_load_config(void)
{
	git_config(survey_load_config_cb, NULL);
}

/*
 * Stats on the set of refs that we found.
 */
struct survey_stats_refs {
	uint32_t cnt_total;
	uint32_t cnt_lightweight_tags;
	uint32_t cnt_annotated_tags;
	uint32_t cnt_branches;
	uint32_t cnt_remotes;
	uint32_t cnt_detached;
	uint32_t cnt_other;

	uint32_t cnt_symref;

	uint32_t cnt_packed;
	uint32_t cnt_loose;

	/*
	 * Measure the length of the refnames.  We can look for
	 * potential platform limits.  The partial sums may help us
	 * estimate the size of a haves/wants conversation, since each
	 * refname and a SHA must be transmitted.
	 */
	size_t len_max_local_refname;
	size_t len_sum_local_refnames;
	size_t len_max_remote_refname;
	size_t len_sum_remote_refnames;

	struct strintmap refsmap;
};

/*
 * HBIN -- hex binning (histogram bucketing).
 *
 * We create histograms for various counts and sums.  Since we have a
 * wide range of values (objects range in size from 1 to 4G bytes), a
 * linear bucketing is not interesting.  Instead, lets use a
 * log16()-based bucketing.  This gives us a better spread on the low
 * and middle range and a coarse bucketing on the high end.
 *
 * The idea here is that it doesn't matter if you have n 1GB blobs or
 * n/2 1GB blobs and n/2 1.5GB blobs -- either way you have a scaling
 * problem that we want to report on.
 */
#define HBIN_LEN (sizeof(unsigned long) * 2)
#define HBIN_MASK (0xF)
#define HBIN_SHIFT (4)

static int hbin(unsigned long value)
{
	int k;

	for (k = 0; k < HBIN_LEN; k++) {
		if ((value & ~(HBIN_MASK)) == 0)
			return k;
		value >>= HBIN_SHIFT;
	}

	return 0; /* should not happen */
}

/*
 * QBIN -- base4 binning (histogram bucketing).
 *
 * This is the same idea as the above, but we want better granularity
 * in the low end and don't expect as many large values.
 */
#define QBIN_LEN (sizeof(unsigned long) * 4)
#define QBIN_MASK (0x3)
#define QBIN_SHIFT (2)

static int qbin(unsigned long value)
{
	int k;

	for (k = 0; k < QBIN_LEN; k++) {
		if ((value & ~(QBIN_MASK)) == 0)
			return k;
		value >>= (QBIN_SHIFT);
	}

	return 0; /* should not happen */
}

/*
 * histogram bin for objects.
 */
struct obj_hist_bin {
	uint64_t sum_size;      /* sum(object_size) for all objects in this bin */
	uint64_t sum_disk_size; /* sum(on_disk_size) for all objects in this bin */
	uint32_t cnt_seen;      /* number seen in this bin */
};

static void incr_obj_hist_bin(struct obj_hist_bin *pbin,
			       unsigned long object_length,
			       off_t disk_sizep)
{
	pbin->sum_size += object_length;
	pbin->sum_disk_size += disk_sizep;
	pbin->cnt_seen++;
}

/*
 * Remember the largest n objects for some scaling dimension.  This
 * could be the observed object size or number of entries in a tree.
 * We'll use this to generate a sorted vector in the output for that
 * dimension.
 */
struct large_item {
	uint64_t size;
	struct object_id oid;

	/*
	 * For blobs and trees the name field is the pathname of the
	 * file or directory.  Root trees will have a zero-length
	 * name.  The name field is not currenly used for commits.
	 */
	struct strbuf *name;

	/*
	 * For blobs and trees remember the transient commit from
	 * the treewalk so that we can say that this large item
	 * first appeared in this commit (relative to the treewalk
	 * order).
	 */
	struct object_id containing_commit_oid;

	/*
	 * Lookup `containing_commit_oid` using `git name-rev`.
	 * Lazy allocate this post-treewalk.
	 */
	struct strbuf *name_rev;
};

struct large_item_vec {
	char *dimension_label;
	char *item_label;
	uint64_t nr_items;
	struct large_item items[FLEX_ARRAY]; /* nr_items */
};

static struct large_item_vec *alloc_large_item_vec(const char *dimension_label,
						   const char *item_label,
						   uint64_t nr_items)
{
	struct large_item_vec *vec;
	size_t flex_len = nr_items * sizeof(struct large_item);
	size_t k;

	if (!nr_items)
		return NULL;

	vec = xcalloc(1, (sizeof(struct large_item_vec) + flex_len));
	vec->dimension_label = strdup(dimension_label);
	vec->item_label = strdup(item_label);
	vec->nr_items = nr_items;

	for (k = 0; k < nr_items; k++) {
		struct strbuf *p = xcalloc(1, sizeof(struct strbuf));
		strbuf_init(p, 0);
		vec->items[k].name = p;
	}

	return vec;
}

static void free_large_item_vec(struct large_item_vec *vec)
{
	size_t k;

	for (k = 0; k < vec->nr_items; k++) {
		strbuf_release(vec->items[k].name);
		free(vec->items[k].name);

		if (vec->items[k].name_rev) {
			strbuf_release(vec->items[k].name_rev);
			free(vec->items[k].name_rev);
		}
	}

	free(vec->dimension_label);
	free(vec->item_label);
	free(vec);
}

static void maybe_insert_large_item(struct large_item_vec *vec,
				    uint64_t size,
				    struct object_id *oid,
				    const char *name,
				    const struct object_id *containing_commit_oid)
{
	struct strbuf *pbuf_temp;
	size_t rest_len;
	size_t k;

	if (!vec || !vec->nr_items)
		return;

	/*
	 * Since the odds an object being among the largest n
	 * is small, shortcut and see if it is smaller than
	 * the smallest one in our set and quickly reject it.
	 */
	if (size < vec->items[vec->nr_items - 1].size)
		return;

	for (k = 0; k < vec->nr_items; k++) {
		if (size < vec->items[k].size)
			continue;

		/*
		 * The last large_item in the vector is about to be
		 * overwritten by the previous one during the shift.
		 * Steal its allocated strbuf and reuse it.
		 *
		 * We can ignore .name_rev because it will not be
		 * allocated until after the treewalk.
		 */
		pbuf_temp = vec->items[vec->nr_items - 1].name;
		strbuf_reset(pbuf_temp);
		if (name && *name)
			strbuf_addstr(pbuf_temp, name);

		/* push items[k..] down one and insert data for this item here */

		rest_len = (vec->nr_items - k - 1) * sizeof(struct large_item);
		if (rest_len)
			memmove(&vec->items[k + 1], &vec->items[k], rest_len);

		memset(&vec->items[k], 0, sizeof(struct large_item));
		vec->items[k].size = size;
		oidcpy(&vec->items[k].oid, oid);
		oidcpy(&vec->items[k].containing_commit_oid, containing_commit_oid);

		vec->items[k].name = pbuf_temp;

		return;
	}
}

/*
 * Try to run `git name-rev` on each of the containing-commit-oid's
 * in this large-item-vec to get a pretty name for each OID.  Silently
 * ignore errors if it fails because this info is nice to have but not
 * essential.
 */
static void large_item_vec_lookup_name_rev(struct large_item_vec *vec)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf in = STRBUF_INIT;
	struct strbuf out = STRBUF_INIT;
	const char *line;
	size_t k;

	if (!vec || !vec->nr_items)
		return;

	survey_progress_total += vec->nr_items;
	display_progress(survey_progress, survey_progress_total);

	for (k = 0; k < vec->nr_items; k++)
		strbuf_addf(&in, "%s\n", oid_to_hex(&vec->items[k].containing_commit_oid));

	cp.git_cmd = 1;
	strvec_pushl(&cp.args, "name-rev", "--name-only", "--annotate-stdin", NULL);
	if (pipe_command(&cp, in.buf, in.len, &out, 0, NULL, 0)) {
		strbuf_release(&in);
		strbuf_release(&out);
		return;
	}

	line = out.buf;
	k = 0;
	while (*line) {
		const char *eol = strchrnul(line, '\n');

		vec->items[k].name_rev = xcalloc(1, sizeof(struct strbuf));
		strbuf_init(vec->items[k].name_rev, 0);
		strbuf_add(vec->items[k].name_rev, line, (eol - line));

		line = eol + 1;
		k++;
	}

	strbuf_release(&in);
	strbuf_release(&out);
}

/*
 * Common fields for any type of object.
 */
struct survey_stats_base_object {
	uint32_t cnt_seen;

	uint32_t cnt_missing; /* we may have a partial clone. */

	/*
	 * Number of objects grouped by where they are stored on disk.
	 * This is a function of how the ODB is packed.
	 */
	uint32_t cnt_cached;   /* see oi.whence */
	uint32_t cnt_loose;    /* see oi.whence */
	uint32_t cnt_packed;   /* see oi.whence */
	uint32_t cnt_dbcached; /* see oi.whence */

	uint64_t sum_size; /* sum(object_size) */
	uint64_t sum_disk_size; /* sum(disk_size) */

	/*
	 * A histogram of the count of objects, the observed size, and
	 * the on-disk size grouped by the observed size.
	 */
	struct obj_hist_bin size_hbin[HBIN_LEN];
};

/*
 * PBIN -- parent vector binning (histogram bucketing).
 *
 * We create a histogram based upon the number of parents
 * in a commit.  This is a simple linear vector.  It starts
 * at zero for "initial" commits.
 *
 * If a commit has more parents, just put it in the last bin.
 */
#define PBIN_VEC_LEN (17)

struct survey_stats_commits {
	struct survey_stats_base_object base;

	/*
	 * Count of commits with k parents.
	 */
	uint32_t parent_cnt_pbin[PBIN_VEC_LEN];

	struct large_item_vec *vec_largest_by_nr_parents;
	struct large_item_vec *vec_largest_by_size_bytes;
};

/*
 * Stats for reachable trees.
 */
struct survey_stats_trees {
	struct survey_stats_base_object base;

	/*
	 * Keep a vector of the trees with the most number of entries.
	 * This gives us a feel for the width of a tree when there are
	 * gigantic directories.
	 */
	struct large_item_vec *vec_largest_by_nr_entries;

	/*
	 * Keep a vector of the trees with the largest size in bytes.
	 * The contents of this may or may not match items in the other
	 * vector, since entryname length can alter the results.
	 */
	struct large_item_vec *vec_largest_by_size_bytes;

	/*
	 * Computing the sum of the number of entries across all trees
	 * is probably not that interesting.
	 */
	uint64_t sum_entries; /* sum(nr_entries) -- sum across all trees */

	/*
	 * A histogram of the count of trees, the observed size, and
	 * the on-disk size grouped by the number of entries in the tree.
	 */
	struct obj_hist_bin entry_qbin[QBIN_LEN];
};

/*
 * Stats for reachable blobs.
 */
struct survey_stats_blobs {
	struct survey_stats_base_object base;

	/*
	 * Remember the OIDs of the largest n blobs.
	 */
	struct large_item_vec *vec_largest_by_size_bytes;
};

struct survey_stats {
	struct survey_stats_refs    refs;
	struct survey_stats_commits commits;
	struct survey_stats_trees   trees;
	struct survey_stats_blobs   blobs;
};

static struct survey_stats survey_stats = { 0 };

static void do_load_refs(struct ref_array *ref_array)
{
	struct ref_filter filter = REF_FILTER_INIT;
	struct ref_sorting *sorting;
	struct string_list sorting_options = STRING_LIST_INIT_DUP;

	string_list_append(&sorting_options, "objectname");
	sorting = ref_sorting_options(&sorting_options);

	if (survey_opts.refs.want_detached)
		strvec_push(&survey_vec_refs_wanted, "HEAD");

	if (survey_opts.refs.want_all_refs) {
		strvec_push(&survey_vec_refs_wanted, "refs/");
	} else {
		if (survey_opts.refs.want_branches)
			strvec_push(&survey_vec_refs_wanted, "refs/heads/");
		if (survey_opts.refs.want_tags)
			strvec_push(&survey_vec_refs_wanted, "refs/tags/");
		if (survey_opts.refs.want_remotes)
			strvec_push(&survey_vec_refs_wanted, "refs/remotes/");
		if (survey_opts.refs.want_other) {
			strvec_push(&survey_vec_refs_wanted, "refs/notes/");
			strvec_push(&survey_vec_refs_wanted, "refs/stash/");
		}
	}

	filter.name_patterns = survey_vec_refs_wanted.v;
	filter.ignore_case = 0;
	filter.match_as_path = 1;

	if (survey_opts.show_progress) {
		survey_progress_total = 0;
		survey_progress = start_progress(_("Scanning refs..."), 0);
	}

	filter_refs(ref_array, &filter, FILTER_REFS_KIND_MASK);

	if (survey_opts.show_progress) {
		survey_progress_total = ref_array->nr;
		display_progress(survey_progress, survey_progress_total);
	}

	ref_array_sort(sorting, ref_array);

	if (survey_opts.show_progress)
		stop_progress(&survey_progress);

	ref_filter_clear(&filter);
	ref_sorting_release(sorting);
}

/*
 * Populate a "rev_info" with the OIDs of the REFS of interest.
 * The treewalk will start from all of those starting points
 * and walk backwards in the DAG to get the set of all reachable
 * objects from those starting points.
 */
static void load_rev_info(struct rev_info *rev_info,
			  struct ref_array *ref_array)
{
	unsigned int add_flags = 0;
	int k;

	for (k = 0; k < ref_array->nr; k++) {
		struct ref_array_item *p = ref_array->items[k];
		struct object_id peeled;

		switch (p->kind) {
		case FILTER_REFS_TAGS:
			if (!peel_iterated_oid(rev_info->repo, &p->objectname, &peeled))
				add_pending_oid(rev_info, NULL, &peeled, add_flags);
			else
				add_pending_oid(rev_info, NULL, &p->objectname, add_flags);
			break;
		case FILTER_REFS_BRANCHES:
			add_pending_oid(rev_info, NULL, &p->objectname, add_flags);
			break;
		case FILTER_REFS_REMOTES:
			add_pending_oid(rev_info, NULL, &p->objectname, add_flags);
			break;
		case FILTER_REFS_OTHERS:
			/*
			 * This may be a note, stash, or custom namespace branch.
			 */
			add_pending_oid(rev_info, NULL, &p->objectname, add_flags);
			break;
		case FILTER_REFS_DETACHED_HEAD:
			add_pending_oid(rev_info, NULL, &p->objectname, add_flags);
			break;
		default:
			break;
		}
	}
}

static int fill_in_base_object(struct survey_stats_base_object *base,
			       struct object *object,
			       enum object_type type_expected,
			       unsigned long *p_object_length,
			       off_t *p_disk_sizep)
{
	struct object_info oi = OBJECT_INFO_INIT;
	unsigned oi_flags = OBJECT_INFO_FOR_PREFETCH;
	unsigned long object_length = 0;
	off_t disk_sizep = 0;
	enum object_type type;
	int hb;

	base->cnt_seen++;

	oi.typep = &type;
	oi.sizep = &object_length;
	oi.disk_sizep = &disk_sizep;

	if (oid_object_info_extended(the_repository, &object->oid, &oi, oi_flags) < 0 ||
	    type != type_expected) {
		base->cnt_missing++;
		return 1;
	}

	switch (oi.whence) {
	case OI_CACHED:
		base->cnt_cached++;
		break;
	case OI_LOOSE:
		base->cnt_loose++;
		break;
	case OI_PACKED:
		base->cnt_packed++;
		break;
	case OI_DBCACHED:
		base->cnt_dbcached++;
		break;
	default:
		break;
	}

	base->sum_size += object_length;
	base->sum_disk_size += disk_sizep;

	hb = hbin(object_length);
	incr_obj_hist_bin(&base->size_hbin[hb], object_length, disk_sizep);

	if (p_object_length)
		*p_object_length = object_length;
	if (p_disk_sizep)
		*p_disk_sizep = disk_sizep;

	return 0;
}

/*
 * Transient OID of the commit currently being visited
 * during the treewalk.  We can use this to create the
 * <ref>:<pathname> pair when a notable large file was
 * created, for example.
 */
static struct object_id treewalk_transient_commit_oid;

static void traverse_commit_cb(struct commit *commit, void *data)
{
	struct survey_stats_commits *psc = &survey_stats.commits;
	unsigned long object_length;
	unsigned k;

	if ((++survey_progress_total % 1000) == 0)
		display_progress(survey_progress, survey_progress_total);

	oidcpy(&treewalk_transient_commit_oid, &commit->object.oid);

	fill_in_base_object(&psc->base, &commit->object, OBJ_COMMIT, &object_length, NULL);

	k = commit_list_count(commit->parents);

	/*
	 * Send the commit-oid as both the OID and the CONTAINING-COMMIT-OID.
	 * This is somewhat redundant, but lets us later do `git name-rev`
	 * using the containing-oid in a consistent fashion.
	 */
	maybe_insert_large_item(psc->vec_largest_by_nr_parents, k,
				&commit->object.oid, NULL,
				&commit->object.oid);
	maybe_insert_large_item(psc->vec_largest_by_size_bytes, object_length,
				&commit->object.oid, NULL,
				&commit->object.oid);

	if (k >= PBIN_VEC_LEN)
		k = PBIN_VEC_LEN - 1;
	psc->parent_cnt_pbin[k]++;
}

static void traverse_object_cb_tree(struct object *obj, const char *name)
{
	struct survey_stats_trees *pst = &survey_stats.trees;
	unsigned long object_length;
	off_t disk_sizep;
	struct tree_desc desc;
	struct name_entry entry;
	struct tree *tree;
	int nr_entries;
	int qb;

	if (fill_in_base_object(&pst->base, obj, OBJ_TREE, &object_length, &disk_sizep))
		return;

	tree = lookup_tree(the_repository, &obj->oid);
	if (!tree)
		return;
	init_tree_desc(&desc, &obj->oid, tree->buffer, tree->size);
	nr_entries = 0;
	while (tree_entry(&desc, &entry))
		nr_entries++;

	pst->sum_entries += nr_entries;

	maybe_insert_large_item(pst->vec_largest_by_nr_entries, nr_entries,
				&obj->oid, name,
				&treewalk_transient_commit_oid);
	maybe_insert_large_item(pst->vec_largest_by_size_bytes, object_length,
				&obj->oid, name,
				&treewalk_transient_commit_oid);

	qb = qbin(nr_entries);
	incr_obj_hist_bin(&pst->entry_qbin[qb], object_length, disk_sizep);
}

static void traverse_object_cb_blob(struct object *obj, const char *name)
{
	struct survey_stats_blobs *psb = &survey_stats.blobs;
	unsigned long object_length;

	fill_in_base_object(&psb->base, obj, OBJ_BLOB, &object_length, NULL);

	maybe_insert_large_item(psb->vec_largest_by_size_bytes, object_length,
				&obj->oid, name,
				&treewalk_transient_commit_oid);
}

static void traverse_object_cb(struct object *obj, const char *name, void *data)
{
	if ((++survey_progress_total % 1000) == 0)
		display_progress(survey_progress, survey_progress_total);

	switch (obj->type) {
	case OBJ_TREE:
		traverse_object_cb_tree(obj, name);
		return;
	case OBJ_BLOB:
		traverse_object_cb_blob(obj, name);
		return;
	case OBJ_TAG:    /* ignore     -- counted when loading REFS */
	case OBJ_COMMIT: /* ignore/bug -- seen in the other callback */
	default:         /* ignore/bug -- unknown type */
		return;
	}
}

/*
 * Treewalk all of the commits and objects reachable from the
 * set of refs.
 */
static void do_treewalk_reachable(struct ref_array *ref_array)
{
	struct rev_info rev_info = REV_INFO_INIT;

	repo_init_revisions(the_repository, &rev_info, NULL);
	rev_info.tree_objects = 1;
	rev_info.blob_objects = 1;
	rev_info.tree_blobs_in_commit_order = 1;
	load_rev_info(&rev_info, ref_array);
	if (prepare_revision_walk(&rev_info))
		die(_("revision walk setup failed"));

	if (survey_opts.show_progress) {
		survey_progress_total = 0;
		survey_progress = start_progress(_("Walking reachable objects..."), 0);
	}

	oidcpy(&treewalk_transient_commit_oid, null_oid());
	traverse_commit_list(&rev_info,
			     traverse_commit_cb,
			     traverse_object_cb,
			     NULL);
	oidcpy(&treewalk_transient_commit_oid, null_oid());

	if (survey_opts.show_progress)
		stop_progress(&survey_progress);

	release_revisions(&rev_info);
}

/*
 * If we want this type of ref, increment counters and return 1.
 */
static int maybe_count_ref(struct repository *r, struct ref_array_item *p)
{
	struct survey_refs_wanted *rw = &survey_opts.refs;
	struct survey_stats_refs *prs = &survey_stats.refs;
	struct object_id peeled;

	/*
	 * Classify the ref using the `kind` value.  Note that
	 * p->kind was populated by `ref_kind_from_refname()`
	 * based strictly on the refname.  This only knows about
	 * the basic stock categories and returns FILTER_REFS_OTHERS
	 * for notes, stashes, and any custom namespaces (like
	 * "refs/prefetch/").
	 */
	switch (p->kind) {
	case FILTER_REFS_TAGS:
		if (rw->want_all_refs || rw->want_tags) {
			/*
			 * NEEDSWORK: Both types of tags have the same
			 * "refs/tags/" prefix. Do we want to count them
			 * in separate buckets in the refsmap?
			 */
			strintmap_incr(&prs->refsmap, "refs/tags/", 1);

			if (!peel_iterated_oid(r, &p->objectname, &peeled))
				prs->cnt_annotated_tags++;
			else
				prs->cnt_lightweight_tags++;

			return 1;
		}
		return 0;

	case FILTER_REFS_BRANCHES:
		if (rw->want_all_refs || rw->want_branches) {
			strintmap_incr(&prs->refsmap, "refs/heads/", 1);

			prs->cnt_branches++;
			return 1;
		}
		return 0;

	case FILTER_REFS_REMOTES:
		if (rw->want_all_refs || rw->want_remotes) {
			/*
			 * For the refsmap, group them by the "refs/remotes/<remote>/".
			 * For example:
			 *   "refs/remotes/origin/..."
			 */
			if (starts_with(p->refname, "refs/remotes/")) {
				struct strbuf buf = STRBUF_INIT;
				int begin = strlen("refs/remotes/");
				size_t j;

				strbuf_addstr(&buf, p->refname);
				for (j = begin; j < buf.len; j++) {
					if (buf.buf[j] == '/') {
						strbuf_setlen(&buf, j+1);
						break;
					}
				}
				strintmap_incr(&prs->refsmap, buf.buf, 1);
				strbuf_release(&buf);
			}

			prs->cnt_remotes++;
			return 1;
		}
		return 0;

	case FILTER_REFS_OTHERS:
		if (rw->want_all_refs || rw->want_other) {
			/*
			 * For the refsmap, group them by their "refs/<class>/".
			 * For example:
			 *   "refs/notes/..."
			 *   "refs/stash/..."
			 *   "refs/<custom>/..."
			 */
			if (starts_with(p->refname, "refs/")) {
				struct strbuf buf = STRBUF_INIT;
				int begin = strlen("refs/");
				size_t j;

				strbuf_addstr(&buf, p->refname);
				for (j = begin; j < buf.len; j++) {
					if (buf.buf[j] == '/') {
						strbuf_setlen(&buf, j+1);
						break;
					}
				}
				strintmap_incr(&prs->refsmap, buf.buf, 1);
				strbuf_release(&buf);
			}

			prs->cnt_other++;
			return 1;
		}
		return 0;

	case FILTER_REFS_DETACHED_HEAD:
		if (rw->want_all_refs || rw->want_detached) {
			strintmap_incr(&prs->refsmap, p->refname, 1);

			prs->cnt_detached++;
			return 1;
		}
		return 0;

	default:
		if (rw->want_all_refs) {
			strintmap_incr(&prs->refsmap, p->refname, 1); /* probably "HEAD" */

			return 1;
		}
		return 0;
	}
}

/*
 * Calculate stats on the set of refs that we found.
 */
static void do_calc_stats_refs(struct repository *r, struct ref_array *ref_array)
{
	struct survey_stats_refs *prs = &survey_stats.refs;
	int k;

	strintmap_init(&prs->refsmap, 0);

	for (k = 0; k < ref_array->nr; k++) {
		struct ref_array_item *p = ref_array->items[k];
		size_t len;

		if (!maybe_count_ref(r, p))
			continue;

		prs->cnt_total++;

		/*
		 * SymRefs are somewhat orthogonal to the above
		 * classification (e.g. "HEAD" --> detached
		 * and "refs/remotes/origin/HEAD" --> remote) so
		 * our totals will already include them.
		 */
		if (p->flag & REF_ISSYMREF)
			prs->cnt_symref++;

		/*
		 * Where/how is the ref stored in GITDIR.
		 */
		if (p->flag & REF_ISPACKED)
			prs->cnt_packed++;
		else
			prs->cnt_loose++;

		len = strlen(p->refname);

		if (p->kind == FILTER_REFS_REMOTES) {
			prs->len_sum_remote_refnames += len;
			if (len > prs->len_max_remote_refname)
				prs->len_max_remote_refname = len;
		} else {
			prs->len_sum_local_refnames += len;
			if (len > prs->len_max_local_refname)
				prs->len_max_local_refname = len;
		}
	}
}

static void do_lookup_name_rev(void)
{
	if (survey_opts.show_progress) {
		survey_progress_total = 0;
		survey_progress = start_progress(_("Resolving name-revs..."), 0);
	}

	large_item_vec_lookup_name_rev(survey_stats.commits.vec_largest_by_nr_parents);
	large_item_vec_lookup_name_rev(survey_stats.commits.vec_largest_by_size_bytes);

	large_item_vec_lookup_name_rev(survey_stats.trees.vec_largest_by_nr_entries);
	large_item_vec_lookup_name_rev(survey_stats.trees.vec_largest_by_size_bytes);

	large_item_vec_lookup_name_rev(survey_stats.blobs.vec_largest_by_size_bytes);

	if (survey_opts.show_progress)
		stop_progress(&survey_progress);
}

/*
 * The REFS phase:
 *
 * Load the set of requested refs and assess them for scalablity problems.
 * Use that set to start a treewalk to all reachable objects and assess
 * them.
 *
 * This data will give us insights into the repository itself (the number
 * of refs, the size and shape of the DAG, the number and size of the
 * objects).
 *
 * Theoretically, this data is independent of the on-disk representation
 * (e.g. independent of packing concerns).
 */
static void survey_phase_refs(struct repository *r)
{
	struct ref_array ref_array = { 0 };

	trace2_region_enter("survey", "phase/refs", the_repository);
	do_load_refs(&ref_array);
	trace2_region_leave("survey", "phase/refs", the_repository);

	trace2_region_enter("survey", "phase/treewalk", the_repository);
	do_treewalk_reachable(&ref_array);
	trace2_region_leave("survey", "phase/treewalk", the_repository);

	trace2_region_enter("survey", "phase/calcstats", the_repository);
	do_calc_stats_refs(r, &ref_array);
	trace2_region_leave("survey", "phase/calcstats", the_repository);

	trace2_region_enter("survey", "phase/namerev", the_repository);
	do_lookup_name_rev();
	trace2_region_enter("survey", "phase/namerev", the_repository);

	ref_array_clear(&ref_array);
}

static void json_refs_section(struct json_writer *jw_top, int pretty, int want_trace2)
{
	struct survey_stats_refs *prs = &survey_stats.refs;
	struct json_writer jw_refs = JSON_WRITER_INIT;
	int k;

	jw_object_begin(&jw_refs, pretty);
	{
		jw_object_intmax(&jw_refs, "count", prs->cnt_total);

		jw_object_inline_begin_object(&jw_refs, "count_by_type");
		{
			if (survey_opts.refs.want_branches)
				jw_object_intmax(&jw_refs, "branches", prs->cnt_branches);
			if (survey_opts.refs.want_tags) {
				jw_object_intmax(&jw_refs, "lightweight_tags", prs->cnt_lightweight_tags);
				jw_object_intmax(&jw_refs, "annotated_tags", prs->cnt_annotated_tags);
			}
			if (survey_opts.refs.want_remotes)
				jw_object_intmax(&jw_refs, "remotes", prs->cnt_remotes);
			if (survey_opts.refs.want_detached)
				jw_object_intmax(&jw_refs, "detached", prs->cnt_detached);
			if (survey_opts.refs.want_other)
				jw_object_intmax(&jw_refs, "other", prs->cnt_other);

			/*
			 * SymRefs are somewhat orthogonal to
			 * the above classification
			 * (e.g. "HEAD" --> detached and
			 * "refs/remotes/origin/HEAD" -->
			 * remote) so the above classified
			 * counts will already include them,
			 * but it is less confusing to display
			 * them here than to create a whole
			 * new section.
			 */
			if (prs->cnt_symref)
				jw_object_intmax(&jw_refs, "symrefs", prs->cnt_symref);
		}
		jw_end(&jw_refs);

		jw_object_inline_begin_object(&jw_refs, "count_by_storage");
		{
			jw_object_intmax(&jw_refs, "loose_refs", prs->cnt_loose);
			jw_object_intmax(&jw_refs, "packed_refs", prs->cnt_packed);
		}
		jw_end(&jw_refs);

		jw_object_inline_begin_object(&jw_refs, "refname_length");
		{
			if (prs->len_sum_local_refnames) {
				jw_object_intmax(&jw_refs, "max_local", prs->len_max_local_refname);
				jw_object_intmax(&jw_refs, "sum_local", prs->len_sum_local_refnames);
			}
			if (prs->len_sum_remote_refnames) {
				jw_object_intmax(&jw_refs, "max_remote", prs->len_max_remote_refname);
				jw_object_intmax(&jw_refs, "sum_remote", prs->len_sum_remote_refnames);
			}
		}
		jw_end(&jw_refs);

		jw_object_inline_begin_array(&jw_refs, "requested");
		{
			for (k = 0; k < survey_vec_refs_wanted.nr; k++)
				jw_array_string(&jw_refs, survey_vec_refs_wanted.v[k]);
		}
		jw_end(&jw_refs);

		jw_object_inline_begin_array(&jw_refs, "count_by_class");
		{
			struct hashmap_iter iter;
			struct strmap_entry *entry;

			strintmap_for_each_entry(&prs->refsmap, &iter, entry) {
				const char *key = entry->key;
				intptr_t count = (intptr_t)entry->value;
				int value = count;
				jw_array_inline_begin_object(&jw_refs);
				{
					jw_object_string(&jw_refs, "class", key);
					jw_object_intmax(&jw_refs, "count", value);
				}
				jw_end(&jw_refs);
			}
		}
		jw_end(&jw_refs);
	}
	jw_end(&jw_refs);

	if (jw_top)
		jw_object_sub_jw(jw_top, "refs", &jw_refs);

	if (want_trace2)
		trace2_data_json("survey", the_repository, "refs", &jw_refs);

	jw_release(&jw_refs);
}

#define JW_OBJ_INT_NZ(jw, key, value) do { if (value) jw_object_intmax((jw), (key), (value)); } while (0)

static void write_qbin_json(struct json_writer *jw, const char *label,
			    struct obj_hist_bin qbin[QBIN_LEN])
{
	struct strbuf buf = STRBUF_INIT;
	uint32_t lower = 0;
	uint32_t upper = QBIN_MASK;
	int k;

	jw_object_inline_begin_object(jw, label);
	{
		for (k = 0; k < QBIN_LEN; k++) {
			struct obj_hist_bin *p = &qbin[k];
			uint32_t lower_k = lower;
			uint32_t upper_k = upper;

			lower = upper+1;
			upper = (upper << QBIN_SHIFT) + QBIN_MASK;

			if (!p->cnt_seen)
				continue;

			strbuf_reset(&buf);
			strbuf_addf(&buf, "Q%02d", k);
			jw_object_inline_begin_object(jw, buf.buf);
			{
				jw_object_intmax(jw, "count", p->cnt_seen);
				jw_object_intmax(jw, "sum_size", p->sum_size);
				jw_object_intmax(jw, "sum_disk_size", p->sum_disk_size);

				/* maybe only include these in verbose mode */
				jw_object_intmax(jw, "qbin_lower", lower_k);
				jw_object_intmax(jw, "qbin_upper", upper_k);
			}
			jw_end(jw);
		}
	}
	jw_end(jw);

	strbuf_release(&buf);
}

static void write_hbin_json(struct json_writer *jw, const char *label,
			    struct obj_hist_bin hbin[HBIN_LEN])
{
	struct strbuf buf = STRBUF_INIT;
	uint32_t lower = 0;
	uint32_t upper = HBIN_MASK;
	int k;

	jw_object_inline_begin_object(jw, label);
	{
		for (k = 0; k < HBIN_LEN; k++) {
			struct obj_hist_bin *p = &hbin[k];
			uint32_t lower_k = lower;
			uint32_t upper_k = upper;

			lower = upper+1;
			upper = (upper << HBIN_SHIFT) + HBIN_MASK;

			if (!p->cnt_seen)
				continue;

			strbuf_reset(&buf);
			strbuf_addf(&buf, "H%d", k);
			jw_object_inline_begin_object(jw, buf.buf);
			{
				jw_object_intmax(jw, "count", p->cnt_seen);
				jw_object_intmax(jw, "sum_size", p->sum_size);
				jw_object_intmax(jw, "sum_disk_size", p->sum_disk_size);

				/* maybe only include these in verbose mode */
				jw_object_intmax(jw, "hbin_lower", lower_k);
				jw_object_intmax(jw, "hbin_upper", upper_k);
			}
			jw_end(jw);
		}
	}
	jw_end(jw);

	strbuf_release(&buf);
}

static void write_base_object_json(struct json_writer *jw,
				   struct survey_stats_base_object *base)
{
	jw_object_intmax(jw, "count", base->cnt_seen);

	jw_object_intmax(jw, "sum_size", base->sum_size);
	jw_object_intmax(jw, "sum_disk_size", base->sum_disk_size);

	jw_object_inline_begin_object(jw, "count_by_whence");
	{
		/*
		 * Missing is not technically a "whence" value, but
		 * we don't need to clutter up the results with that
		 * distinction.
		 */
		JW_OBJ_INT_NZ(jw, "missing", base->cnt_missing);

		JW_OBJ_INT_NZ(jw, "cached", base->cnt_cached);
		JW_OBJ_INT_NZ(jw, "loose", base->cnt_loose);
		JW_OBJ_INT_NZ(jw, "packed", base->cnt_packed);
		JW_OBJ_INT_NZ(jw, "dbcached", base->cnt_dbcached);
	}
	jw_end(jw);

	write_hbin_json(jw, "dist_by_size", base->size_hbin);
}

static void write_large_item_vec_json(struct json_writer *jw,
				      struct large_item_vec *vec)
{
	if (!vec || !vec->nr_items)
		return;

	jw_object_inline_begin_array(jw, vec->dimension_label);
	{
		int k;

		for (k = 0; k < vec->nr_items; k++) {
			struct large_item *pk = &vec->items[k];
			if (is_null_oid(&pk->oid))
				break;

			jw_array_inline_begin_object(jw);
			{
				jw_object_intmax(jw, vec->item_label, pk->size);
				jw_object_string(jw, "oid", oid_to_hex(&pk->oid));
				if (pk->name->len)
					jw_object_string(jw, "name", pk->name->buf);
				if (!is_null_oid(&pk->containing_commit_oid))
					jw_object_string(jw, "commit_oid",
							 oid_to_hex(&pk->containing_commit_oid));
				if (pk->name_rev->len)
					jw_object_string(jw, "name_rev",
							 pk->name_rev->buf);
			}
			jw_end(jw);
		}
	}
	jw_end(jw);
}

static void json_commits_section(struct json_writer *jw_top, int pretty, int want_trace2)
{
	struct survey_stats_commits *psc = &survey_stats.commits;
	struct json_writer jw_commits = JSON_WRITER_INIT;

	jw_object_begin(&jw_commits, pretty);
	{
		write_base_object_json(&jw_commits, &psc->base);

		write_large_item_vec_json(&jw_commits, psc->vec_largest_by_nr_parents);
		write_large_item_vec_json(&jw_commits, psc->vec_largest_by_size_bytes);

		jw_object_inline_begin_object(&jw_commits, "count_by_nr_parents");
		{
			struct strbuf parent_key = STRBUF_INIT;
			int k;

			for (k = 0; k < PBIN_VEC_LEN; k++)
				if (psc->parent_cnt_pbin[k]) {
					strbuf_reset(&parent_key);
					strbuf_addf(&parent_key, "P%02d", k);
					jw_object_intmax(&jw_commits, parent_key.buf, psc->parent_cnt_pbin[k]);
				}

			strbuf_release(&parent_key);
		}
		jw_end(&jw_commits);
	}
	jw_end(&jw_commits);

	if (jw_top)
		jw_object_sub_jw(jw_top, "commits", &jw_commits);

	if (want_trace2)
		trace2_data_json("survey", the_repository, "commits", &jw_commits);

	jw_release(&jw_commits);
}

static void json_trees_section(struct json_writer *jw_top, int pretty, int want_trace2)
{
	struct survey_stats_trees *pst = &survey_stats.trees;
	struct json_writer jw_trees = JSON_WRITER_INIT;

	jw_object_begin(&jw_trees, pretty);
	{
		write_base_object_json(&jw_trees, &pst->base);

		jw_object_intmax(&jw_trees, "sum_entries", pst->sum_entries);

		write_large_item_vec_json(&jw_trees, pst->vec_largest_by_nr_entries);
		write_large_item_vec_json(&jw_trees, pst->vec_largest_by_size_bytes);

		write_qbin_json(&jw_trees, "dist_by_nr_entries", pst->entry_qbin);
	}
	jw_end(&jw_trees);

	if (jw_top)
		jw_object_sub_jw(jw_top, "trees", &jw_trees);

	if (want_trace2)
		trace2_data_json("survey", the_repository, "trees", &jw_trees);

	jw_release(&jw_trees);
}

static void json_blobs_section(struct json_writer *jw_top, int pretty, int want_trace2)
{
	struct survey_stats_blobs *psb = &survey_stats.blobs;
	struct json_writer jw_blobs = JSON_WRITER_INIT;

	jw_object_begin(&jw_blobs, pretty);
	{
		write_base_object_json(&jw_blobs, &psb->base);

		write_large_item_vec_json(&jw_blobs, psb->vec_largest_by_size_bytes);
	}
	jw_end(&jw_blobs);

	if (jw_top)
		jw_object_sub_jw(jw_top, "blobs", &jw_blobs);

	if (want_trace2)
		trace2_data_json("survey", the_repository, "blobs", &jw_blobs);

	jw_release(&jw_blobs);
}

static void survey_print_json(void)
{
	struct json_writer jw_top = JSON_WRITER_INIT;
	int pretty = 1;

	jw_object_begin(&jw_top, pretty);
	{
		json_refs_section(&jw_top, pretty, 0);
		json_commits_section(&jw_top, pretty, 0);
		json_trees_section(&jw_top, pretty, 0);
		json_blobs_section(&jw_top, pretty, 0);
	}
	jw_end(&jw_top);

	printf("%s\n", jw_top.json.buf);

	jw_release(&jw_top);
}

static void survey_emit_trace2(void)
{
	if (!trace2_is_enabled())
		return;

	json_refs_section(NULL, 0, 1);
	json_commits_section(NULL, 0, 1);
	json_trees_section(NULL, 0, 1);
	json_blobs_section(NULL, 0, 1);
}

/*
 * Print all of the stats that we have collected in a more pretty format.
 */
static void survey_print_results_pretty(void)
{
	printf("TODO....\n");
}

int cmd_survey(int argc, const char **argv, const char *prefix)
{
	survey_load_config();

	argc = parse_options(argc, argv, prefix, survey_options, survey_usage, 0);

	prepare_repo_settings(the_repository);

	if (survey_opts.show_progress < 0)
		survey_opts.show_progress = isatty(2);
	fixup_refs_wanted();

	if (survey_opts.show_largest_commits_by_nr_parents)
		survey_stats.commits.vec_largest_by_nr_parents =
			alloc_large_item_vec(
				"largest_commits_by_nr_parents",
				"nr_parents",
				survey_opts.show_largest_commits_by_nr_parents);
	if (survey_opts.show_largest_commits_by_size_bytes)
		survey_stats.commits.vec_largest_by_size_bytes =
			alloc_large_item_vec(
				"largest_commits_by_size_bytes",
				"size",
				survey_opts.show_largest_commits_by_size_bytes);

	if (survey_opts.show_largest_trees_by_nr_entries)
		survey_stats.trees.vec_largest_by_nr_entries =
			alloc_large_item_vec(
				"largest_trees_by_nr_entries",
				"nr_entries",
				survey_opts.show_largest_trees_by_nr_entries);
	if (survey_opts.show_largest_trees_by_size_bytes)
		survey_stats.trees.vec_largest_by_size_bytes =
			alloc_large_item_vec(
				"largest_trees_by_size_bytes",
				"size",
				survey_opts.show_largest_trees_by_size_bytes);

	if (survey_opts.show_largest_blobs_by_size_bytes)
		survey_stats.blobs.vec_largest_by_size_bytes =
			alloc_large_item_vec(
				"largest_blobs_by_size_bytes",
				"size",
				survey_opts.show_largest_blobs_by_size_bytes);

	survey_phase_refs(the_repository);

	survey_emit_trace2();
	if (survey_opts.show_json)
		survey_print_json();
	else
		survey_print_results_pretty();

	strvec_clear(&survey_vec_refs_wanted);
	free_large_item_vec(survey_stats.commits.vec_largest_by_nr_parents);
	free_large_item_vec(survey_stats.commits.vec_largest_by_size_bytes);
	free_large_item_vec(survey_stats.trees.vec_largest_by_nr_entries);
	free_large_item_vec(survey_stats.trees.vec_largest_by_size_bytes);
	free_large_item_vec(survey_stats.blobs.vec_largest_by_size_bytes);

	return 0;
}
