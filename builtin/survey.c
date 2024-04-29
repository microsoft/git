#include "builtin.h"
#include "config.h"
#include "parse-options.h"
#include "progress.h"
#include "ref-filter.h"
#include "strvec.h"
#include "trace2.h"

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

	.refs.want_all_refs = -1,

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

	ref_array_clear(&ref_array);
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

	strvec_clear(&survey_vec_refs_wanted);

	return 0;
}
