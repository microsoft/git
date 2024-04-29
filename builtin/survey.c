#include "builtin.h"
#include "config.h"
#include "environment.h"
#include "json-writer.h"
#include "list-objects.h"
#include "object-name.h"
#include "object-store.h"
#include "parse-options.h"
#include "progress.h"
#include "ref-filter.h"
#include "refs.h"
#include "revision.h"
#include "strbuf.h"
#include "strmap.h"
#include "strvec.h"
#include "trace2.h"
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
	struct survey_refs_wanted refs;
};

static struct survey_opts survey_opts = {
	.verbose = 0,
	.show_progress = -1, /* defaults to isatty(2) */

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

	OPT_BOOL_F(0, "all-refs", &survey_opts.refs.want_all_refs, N_("include all refs"),          PARSE_OPT_NONEG),

	OPT_BOOL_F(0, "branches", &survey_opts.refs.want_branches, N_("include branches"),          PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "tags",     &survey_opts.refs.want_tags,     N_("include tags"),              PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "remotes",  &survey_opts.refs.want_remotes,  N_("include all remotes refs"),  PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "detached", &survey_opts.refs.want_detached, N_("include detached HEAD"),     PARSE_OPT_NONEG),
	OPT_BOOL_F(0, "other",    &survey_opts.refs.want_other,    N_("include notes and stashes"), PARSE_OPT_NONEG),

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

struct survey_stats {
	struct survey_stats_refs refs;
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

static void traverse_commit_cb(struct commit *commit, void *data)
{
	if ((++survey_progress_total % 1000) == 0)
		display_progress(survey_progress, survey_progress_total);
}

static void traverse_object_cb(struct object *obj, const char *name, void *data)
{
	if ((++survey_progress_total % 1000) == 0)
		display_progress(survey_progress, survey_progress_total);
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
	load_rev_info(&rev_info, ref_array);
	if (prepare_revision_walk(&rev_info))
		die(_("revision walk setup failed"));

	if (survey_opts.show_progress) {
		survey_progress_total = 0;
		survey_progress = start_progress(_("Walking reachable objects..."), 0);
	}

	traverse_commit_list(&rev_info,
			     traverse_commit_cb,
			     traverse_object_cb,
			     NULL);

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

static void survey_print_json(void)
{
	struct json_writer jw_top = JSON_WRITER_INIT;
	int pretty = 1;

	jw_object_begin(&jw_top, pretty);
	{
		json_refs_section(&jw_top, pretty, 0);
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
}

int cmd_survey(int argc, const char **argv, const char *prefix)
{
	survey_load_config();

	argc = parse_options(argc, argv, prefix, survey_options, survey_usage, 0);

	prepare_repo_settings(the_repository);

	if (survey_opts.show_progress < 0)
		survey_opts.show_progress = isatty(2);
	fixup_refs_wanted();

	survey_phase_refs(the_repository);

	survey_emit_trace2();
	survey_print_json();

	strvec_clear(&survey_vec_refs_wanted);

	return 0;
}
