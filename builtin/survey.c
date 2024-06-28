#define USE_THE_REPOSITORY_VARIABLE

#include "builtin.h"
#include "color.h"
#include "exec-cmd.h"
#include "gettext.h"
#include "parse-options.h"
#include "strvec.h"

static const char * const survey_usage[] = {
	N_("(DEPRECATED!) git survey <options>"),
	NULL,
};

/*
 * `git survey` has been superseded by `git repo structure`. To keep
 * older callers working while the migration completes, accept the
 * `git survey` command line, translate the options into the
 * equivalent `git repo structure` invocation, and re-exec.
 */
int cmd_survey(int argc, const char **argv, const char *prefix,
	       struct repository *repo UNUSED)
{
	int verbose = 0;
	int show_progress = -1;
	int top_nr = 10;
	int want_all_refs = -1;
	int want_branches = -1;
	int want_tags = -1;
	int want_remotes = -1;
	int want_detached = -1;
	int want_other = -1;
	struct strvec child_argv = STRVEC_INIT;
	struct option options[] = {
		OPT__VERBOSE(&verbose, N_("verbose output (ignored)")),
		OPT_BOOL(0, "progress", &show_progress, N_("show progress")),
		OPT_INTEGER('n', "top", &top_nr,
			    N_("number of entries to include in "
			       "detail tables")),
		OPT_BOOL_F(0, "all-refs", &want_all_refs,
			   N_("include all refs"), PARSE_OPT_NONEG),
		OPT_BOOL_F(0, "branches", &want_branches,
			   N_("include branches"), PARSE_OPT_NONEG),
		OPT_BOOL_F(0, "tags", &want_tags,
			   N_("include tags"), PARSE_OPT_NONEG),
		OPT_BOOL_F(0, "remotes", &want_remotes,
			   N_("include remote refs"), PARSE_OPT_NONEG),
		OPT_BOOL_F(0, "detached", &want_detached,
			   N_("include detached HEAD (ignored)"),
			   PARSE_OPT_NONEG),
		OPT_BOOL_F(0, "other", &want_other,
			   N_("include notes and stashes"), PARSE_OPT_NONEG),
		OPT_END(),
	};

	argc = parse_options(argc, argv, prefix, options, survey_usage, 0);
	if (top_nr < 0)
		die(_("--top=<n> must be non-negative"));
	if (argc)
		usage(_("'git survey' takes no positional arguments"));

	warning(_("'git survey' is deprecated; "
		  "use 'git repo structure' instead"));
	if (verbose)
		warning(_("--verbose is ignored by 'git repo structure'"));
	if (want_detached != -1)
		warning(_("--detached is ignored by 'git repo structure'"));

	strvec_pushl(&child_argv, "repo", "structure", NULL);
	if (show_progress == 1)
		strvec_push(&child_argv, "--progress");
	else if (show_progress == 0)
		strvec_push(&child_argv, "--no-progress");
	strvec_pushf(&child_argv, "--top=%d", top_nr);

	/*
	 * Survey's default ref scope is branches+tags+remotes (not "other").
	 * `--all-refs` widens to literally everything; the per-kind flags
	 * select specific subsets. `git repo structure` defaults to all
	 * refs and accepts a repeatable --ref-filter=<pattern>, so the
	 * translation is straightforward.
	 */
	if (want_all_refs != 1) {
		int branches = want_branches == 1;
		int tags = want_tags == 1;
		int remotes = want_remotes == 1;
		int other = want_other == 1;

		if (!branches && !tags && !remotes && !other)
			branches = tags = remotes = 1;

		if (branches)
			strvec_push(&child_argv,
				    "--ref-filter=refs/heads/*");
		if (tags)
			strvec_push(&child_argv,
				    "--ref-filter=refs/tags/*");
		if (remotes)
			strvec_push(&child_argv,
				    "--ref-filter=refs/remotes/*");
		if (other) {
			strvec_push(&child_argv,
				    "--ref-filter=refs/notes/*");
			strvec_push(&child_argv,
				    "--ref-filter=refs/stash");
		}
	}

	execv_git_cmd(child_argv.v);
	/* unreachable: execv_git_cmd dies on failure */
	strvec_clear(&child_argv);
	return 1;
}

/*
 * NEEDSWORK: So far, I only have iteration on the requested set of
 * refs and treewalk/reachable objects on that set of refs.  The
 * following is a bit of a laundry list of things that I'd like to
 * add.
 *
 * [] Dump stats on all of the packfiles. The number and size of each.
 *    Whether each is in the .git directory or in an alternate.  The
 *    state of the IDX or MIDX files and etc.  Delta chain stats.  All
 *    of this data is relative to the "lived-in" state of the
 *    repository.  Stuff that may change after a GC or repack.
 *
 * [] Clone and Index stats. partial, shallow, sparse-checkout,
 *    sparse-index, etc.  Hydration stats.
 *
 * [] Dump stats on each remote.  When we fetch from a remote the size
 *    of the response is related to the set of haves on the server.
 *    You can see this in `GIT_TRACE_CURL=1 git fetch`. We get a
 *    `ls-refs` payload that lists all of the branches and tags on the
 *    server, so at a minimum the RefName and SHA for each. But for
 *    annotated tags we also get the peeled SHA.  The size of this
 *    overhead on every fetch is proporational to the size of the `git
 *    ls-remote` response (roughly, although the latter repeats the
 *    RefName of the peeled tag).  If, for example, you have 500K refs
 *    on a remote, you're going to have a long "haves" message, so
 *    every fetch will be slow just because of that overhead (not
 *    counting new objects to be downloaded).
 *
 *    Note that the local set of tags in "refs/tags/" is a union over
 *    all remotes.  However, since most people only have one remote,
 *    we can probaly estimate the overhead value directly from the
 *    size of the set of "refs/tags/" that we visited while building
 *    the `ref_info` and `ref_array` and not need to ask the remote.
 *
 * [] Dump info on the complexity of the DAG.  Criss-cross merges.
 *    The number of edges that must be touched to compute merge bases.
 *    Edge length. The number of parallel lanes in the history that
 *    must be navigated to get to the merge base.  What affects the
 *    cost of the Ahead/Behind computation?  How often do
 *    criss-crosses occur and do they cause various operations to slow
 *    down?
 *
 * [] If there are primary branches (like "main" or "master") are they
 *    always on the left side of merges?  Does the graph have a clean
 *    left edge?  Or are there normal and "backwards" merges?  Do
 *    these cause problems at scale?
 *
 * [] If we have a hierarchy of FI/RI branches like "L1", "L2, ...,
 *    can we learn anything about the shape of the repo around these
 *    FI and RI integrations?
 *
 * [] Do we need a no-PII flag to omit pathnames or branch/tag names
 *    in the various histograms?  (This would turn off --name-rev
 *    too.)
 *
 * [] I have so far avoided adding opinions about individual fields
 *    (such as the way `git-sizer` prints a row of stars or bangs in
 *    the last column).
 *
 *    I'm wondering if that is a job of this executable or if it
 *    should be done in a post-processing step using the JSON output.
 *
 *    My problem with the `git-sizer` approach is that it doesn't give
 *    the (casual) user any information on why it has stars or bangs.
 *    And there isn't a good way to print detailed information in the
 *    ASCII-art tables that would be easy to understand.
 *
 *    [] For example, a large number of refs does not define a cliff.
 *       Performance will drop off (linearly, quadratically, ... ??).
 *       The tool should refer them to article(s) talking about the
 *       different problems that it could cause.  So should `git
 *       survey` just print the number and (implicitly) refer them to
 *       the man page (chapter/verse) or to a tool that will interpret
 *       the number and explain it?
 *
 *    [] Alternatively, should `git survey` do that analysis too and
 *       just print footnotes for each large number?
 *
 *    [] The computation of the raw survey JSON data can take HOURS on
 *       a very large repo (like Windows), so I'm wondering if we
 *       want to keep the opinion portion separate.
 *
 * [] In addition to opinions based on the static data, I would like
 *    to dump the JSON results (or the Trace2 telemetry) into a DB and
 *    aggregate it with other users.
 *
 *    Granted, they should all see the same DAG and the same set of
 *    reachable objects, but we could average across all datasets
 *    generated on a particular date and detect outlier users.
 *
 *    [] Maybe someone cloned from the `_full` endpoint rather than
 *       the limited refs endpoint.
 *
 *    [] Maybe that user is having problems with repacking / GC /
 *       maintenance without knowing it.
 *
 * [] I'd also like to dump use the DB to compare survey datasets over
 *    a time.  How fast is their repository growing and in what ways?
 *
 *    [] I'd rather have the delta analysis NOT be inside `git
 *       survey`, so it makes sense to consider having all of it in a
 *       post-process step.
 *
 * [] Another reason to put the opinion analysis in a post-process
 *    is that it would be easier to generate plots on the data tables.
 *    Granted, we can get plots from telemetry, but a stand-alone user
 *    could run the JSON thru python or jq or something and generate
 *    something nicer than ASCII-art and it could handle cross-referencing
 *    and hyperlinking to helpful information on each issue.
 *
 * [] I think there are several classes of data that we can report on:
 *
 *    [] The "inherit repo properties", such as the shape and size of
 *       the DAG -- these should be universal in each enlistment.
 *
 *    [] The "ODB lived in properties", such as the efficiency
 *       of the repack and things like partial and shallow clone.
 *       These will vary, but indicate health of the ODB.
 *
 *    [] The "index related properties", such as sparse-checkout,
 *       sparse-index, cache-tree, untracked-cache, fsmonitor, and
 *       etc.  These will also vary, but are more like knobs for
 *       the user to adjust.
 *
 *    [] I want to compare these with Matt's "dimensions of scale"
 *       notes and see if there are other pieces of data that we
 *       could compute/consider.
 *
 */
