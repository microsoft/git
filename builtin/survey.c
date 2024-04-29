#include "builtin.h"
#include "config.h"
#include "parse-options.h"

static const char * const survey_usage[] = {
	N_("(EXPERIMENTAL!) git survey <options>"),
	NULL,
};

struct survey_refs_wanted {
	int want_all_refs; /* special override */

	int want_branches;
	int want_tags;
	int want_remotes;
	int want_detached;
	int want_other; /* see FILTER_REFS_OTHERS -- refs/notes/, refs/stash/ */
};

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

int cmd_survey(int argc, const char **argv, const char *prefix)
{
	survey_load_config();

	argc = parse_options(argc, argv, prefix, survey_options, survey_usage, 0);

	prepare_repo_settings(the_repository);

	if (survey_opts.show_progress < 0)
		survey_opts.show_progress = isatty(2);
	fixup_refs_wanted();

	return 0;
}
