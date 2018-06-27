#include "cache.h"
#include "config.h"
#include "version.h"
#include "json-writer.h"
#include "sigchain.h"
#include "argv-array.h"
#include "run-command.h"

#if !defined(STRUCTURED_LOGGING)
/*
 * Structured logging is not available.
 * Stub out all API routines.
 */

#else

#define SLOG_VERSION 0

struct timer_data {
	char *category;
	char *name;
	uint64_t total_ns;
	uint64_t min_ns;
	uint64_t max_ns;
	uint64_t start_ns;
	int count;
	int started;
};

struct timer_data_array {
	struct timer_data **array;
	size_t nr, alloc;
};

static struct timer_data_array my__timers;
static void format_timers(struct json_writer *jw);
static void free_timers(void);

struct aux_data {
	char *category;
	struct json_writer jw;
};

struct aux_data_array {
	struct aux_data **array;
	size_t nr, alloc;
};

static struct aux_data_array my__aux_data;
static void format_and_free_aux_data(struct json_writer *jw);

struct child_data {
	uint64_t start_ns;
	uint64_t end_ns;
	struct json_writer jw_argv;
	unsigned int is_running:1;
	unsigned int is_git_cmd:1;
	unsigned int use_shell:1;
};

struct child_data_array {
	struct child_data **array;
	size_t nr, alloc;
};

static struct child_data_array my__child_data;
static void free_children(void);

static uint64_t my__start_time;
static uint64_t my__exit_time;
static int my__is_config_loaded;
static int my__is_enabled;
static int my__is_pretty;
static int my__signal;
static int my__exit_code;
static int my__pid;
static int my__wrote_start_event;
static int my__log_fd = -1;

static char *my__log_path;
static char *my__command_name;
static char *my__sub_command_name;

static struct argv_array my__argv = ARGV_ARRAY_INIT;
static struct strbuf my__session_id = STRBUF_INIT;
static struct json_writer my__errors = JSON_WRITER_INIT;

struct category_filter
{
	char *categories;
	int want;
};

static struct category_filter my__detail_categories;
static struct category_filter my__timer_categories;
static struct category_filter my__aux_categories;

static void set_want_categories(struct category_filter *cf, const char *value)
{
	FREE_AND_NULL(cf->categories);

	cf->want = git_parse_maybe_bool(value);
	if (cf->want == -1)
		cf->categories = xstrdup(value);
}

static int want_category(const struct category_filter *cf, const char *category)
{
	if (cf->want == 0 || cf->want == 1)
		return cf->want;

	if (!category || !*category)
		return 0;

	return !!strstr(cf->categories, category);
}

/*
 * Compute a new session id for the current process.  Build string
 * with the start time and PID of the current process and append
 * the inherited session id from our parent process (if present).
 * The parent session id may include its parent session id.
 *
 * sid := <start-time> '-' <pid> [ ':' <parent-sid> [ ... ] ]
 */
static void compute_our_sid(void)
{
	const char *parent_sid;

	if (my__session_id.len)
		return;

	/*
	 * A "session id" (SID) is a cheap, unique-enough string to
	 * associate child process with the hierarchy of invoking git
	 * processes.
	 *
	 * This is stronger than a simple parent-pid because we may
	 * have an intermediate shell between a top-level Git command
	 * and a child Git command.  It also isolates from issues
	 * about how the OS recycles PIDs.
	 *
	 * This could be a UUID/GUID, but that is overkill for our
	 * needs here and more expensive to compute.
	 *
	 * Consumers should consider this an unordered opaque string
	 * in case we decide to switch to a real UUID in the future.
	 */
	strbuf_addf(&my__session_id, "%"PRIuMAX"-%"PRIdMAX,
		    (uintmax_t)my__start_time, (intmax_t)my__pid);

	parent_sid = getenv("GIT_SLOG_PARENT_SID");
	if (parent_sid && *parent_sid) {
		strbuf_addch(&my__session_id, ':');
		strbuf_addstr(&my__session_id, parent_sid);
	}

	/*
	 * Install our SID into the environment for our child processes
	 * to inherit.
	 */
	setenv("GIT_SLOG_PARENT_SID", my__session_id.buf, 1);
}

/*
 * Write a single event to the structured log file.
 */
static void emit_event(struct json_writer *jw, const char *event_name)
{
	if (my__log_fd == -1) {
		my__log_fd = open(my__log_path,
				  O_WRONLY | O_APPEND | O_CREAT,
				  0644);
		if (my__log_fd == -1) {
			warning("slog: could not open '%s' for logging: %s",
				my__log_path, strerror(errno));
			my__is_enabled = 0;
			return;
		}
	}

	/*
	 * A properly authored JSON string does not have a final NL
	 * (even when pretty-printing is enabled).  Structured logging
	 * output should look like a series of terminated forms one
	 * per line.  Temporarily append a NL to the buffer so that
	 * the disk write happens atomically.
	 */
	strbuf_addch(&jw->json, '\n');
	if (write(my__log_fd, jw->json.buf, jw->json.len) != jw->json.len)
		warning("slog: could not write event '%s': %s",
			event_name, strerror(errno));

	strbuf_setlen(&jw->json, jw->json.len - 1);
}

static void emit_start_event(void)
{
	struct json_writer jw = JSON_WRITER_INIT;

	/* build "cmd_start" event message */
	jw_object_begin(&jw, my__is_pretty);
	{
		jw_object_string(&jw, "event", "cmd_start");
		jw_object_intmax(&jw, "clock_us", (intmax_t)my__start_time);
		jw_object_intmax(&jw, "pid", (intmax_t)my__pid);
		jw_object_string(&jw, "sid", my__session_id.buf);

		if (my__command_name && *my__command_name)
			jw_object_string(&jw, "command", my__command_name);
		if (my__sub_command_name && *my__sub_command_name)
			jw_object_string(&jw, "sub_command", my__sub_command_name);

		jw_object_inline_begin_array(&jw, "argv");
		{
			int k;
			for (k = 0; k < my__argv.argc; k++)
				jw_array_string(&jw, my__argv.argv[k]);
		}
		jw_end(&jw);
	}
	jw_end(&jw);

	emit_event(&jw, "cmd_start");
	jw_release(&jw);

	my__wrote_start_event = 1;
}

static void emit_exit_event(void)
{
	struct json_writer jw = JSON_WRITER_INIT;
	uint64_t atexit_time = getnanotime() / 1000;

	/* close unterminated forms */
	if (my__errors.json.len)
		jw_end(&my__errors);

	/* build "cmd_exit" event message */
	jw_object_begin(&jw, my__is_pretty);
	{
		jw_object_string(&jw, "event", "cmd_exit");
		jw_object_intmax(&jw, "clock_us", (intmax_t)atexit_time);
		jw_object_intmax(&jw, "pid", (intmax_t)my__pid);
		jw_object_string(&jw, "sid", my__session_id.buf);

		if (my__command_name && *my__command_name)
			jw_object_string(&jw, "command", my__command_name);
		if (my__sub_command_name && *my__sub_command_name)
			jw_object_string(&jw, "sub_command", my__sub_command_name);

		jw_object_inline_begin_array(&jw, "argv");
		{
			int k;
			for (k = 0; k < my__argv.argc; k++)
				jw_array_string(&jw, my__argv.argv[k]);
		}
		jw_end(&jw);

		jw_object_inline_begin_object(&jw, "result");
		{
			jw_object_intmax(&jw, "exit_code", my__exit_code);
			if (my__errors.json.len)
				jw_object_sub_jw(&jw, "errors", &my__errors);

			if (my__signal)
				jw_object_intmax(&jw, "signal", my__signal);

			if (my__exit_time > 0)
				jw_object_intmax(&jw, "elapsed_core_us",
						 my__exit_time - my__start_time);

			jw_object_intmax(&jw, "elapsed_total_us",
					 atexit_time - my__start_time);
		}
		jw_end(&jw);

		jw_object_inline_begin_object(&jw, "version");
		{
			jw_object_string(&jw, "git", git_version_string);
			jw_object_intmax(&jw, "slog", SLOG_VERSION);
		}
		jw_end(&jw);

		if (my__timers.nr) {
			jw_object_inline_begin_object(&jw, "timers");
			format_timers(&jw);
			jw_end(&jw);
		}

		if (my__aux_data.nr) {
			jw_object_inline_begin_object(&jw, "aux");
			format_and_free_aux_data(&jw);
			jw_end(&jw);
		}
	}
	jw_end(&jw);

	emit_event(&jw, "cmd_exit");
	jw_release(&jw);
}

static void emit_detail_event(const char *category, const char *label,
			      uint64_t clock_ns,
			      const struct json_writer *data)
{
	struct json_writer jw = JSON_WRITER_INIT;
	uint64_t clock_us = clock_ns / 1000;

	/* build "detail" event */
	jw_object_begin(&jw, my__is_pretty);
	{
		jw_object_string(&jw, "event", "detail");
		jw_object_intmax(&jw, "clock_us", (intmax_t)clock_us);
		jw_object_intmax(&jw, "pid", (intmax_t)my__pid);
		jw_object_string(&jw, "sid", my__session_id.buf);

		if (my__command_name && *my__command_name)
			jw_object_string(&jw, "command", my__command_name);
		if (my__sub_command_name && *my__sub_command_name)
			jw_object_string(&jw, "sub_command", my__sub_command_name);

		jw_object_inline_begin_object(&jw, "detail");
		{
			jw_object_string(&jw, "category", category);
			jw_object_string(&jw, "label", label);
			if (data)
				jw_object_sub_jw(&jw, "data", data);
		}
		jw_end(&jw);
	}
	jw_end(&jw);

	emit_event(&jw, "detail");
	jw_release(&jw);
}

static int cfg_path(const char *key, const char *value)
{
	if (is_absolute_path(value)) {
		my__log_path = xstrdup(value);
		my__is_enabled = 1;
	} else {
		warning("'%s' must be an absolute path: '%s'",
			key, value);
	}

	return 0;
}

static int cfg_pretty(const char *key, const char *value)
{
	my__is_pretty = git_config_bool(key, value);
	return 0;
}

static int cfg_detail(const char *key, const char *value)
{
	set_want_categories(&my__detail_categories, value);
	return 0;
}

static int cfg_timers(const char *key, const char *value)
{
	set_want_categories(&my__timer_categories, value);
	return 0;
}

static int cfg_aux(const char *key, const char *value)
{
	set_want_categories(&my__aux_categories, value);
	return 0;
}

int slog_default_config(const char *key, const char *value)
{
	const char *sub;

	/*
	 * git_default_config() calls slog_default_config() with "slog.*"
	 * k/v pairs.  git_default_config() MAY or MAY NOT be called when
	 * cmd_<command>() calls git_config().
	 *
	 * Remember if we've ever been called.
	 */
	my__is_config_loaded = 1;

	if (skip_prefix(key, "slog.", &sub)) {
		if (!strcmp(sub, "path"))
			return cfg_path(key, value);
		if (!strcmp(sub, "pretty"))
			return cfg_pretty(key, value);
		if (!strcmp(sub, "detail"))
			return cfg_detail(key, value);
		if (!strcmp(sub, "timers"))
			return cfg_timers(key, value);
		if (!strcmp(sub, "aux"))
			return cfg_aux(key, value);
	}

	return 0;
}

static int lazy_load_config_cb(const char *key, const char * value, void *data)
{
	return slog_default_config(key, value);
}

/*
 * If cmd_<command>() did not cause slog_default_config() to be called
 * during git_config(), we try to lookup our config settings the first
 * time we actually need them.
 *
 * (We do this rather than using read_early_config() at initialization
 * because we want any "-c key=value" arguments to be included.)
 */
static inline void lazy_load_config(void)
{
	if (my__is_config_loaded)
		return;
	my__is_config_loaded = 1;

	read_early_config(lazy_load_config_cb, NULL);
}

int slog_is_enabled(void)
{
	lazy_load_config();

	return my__is_enabled;
}

static void do_final_steps(int in_signal)
{
	static int completed = 0;

	if (completed)
		return;
	completed = 1;

	if (slog_is_enabled()) {
		if (!my__wrote_start_event)
			emit_start_event();
		emit_exit_event();
		my__is_enabled = 0;
	}

	if (my__log_fd != -1)
		close(my__log_fd);
	free(my__log_path);
	free(my__command_name);
	free(my__sub_command_name);
	argv_array_clear(&my__argv);
	jw_release(&my__errors);
	strbuf_release(&my__session_id);
	free_timers();
	free_children();
}

static void slog_atexit(void)
{
	do_final_steps(0);
}

static void slog_signal(int signo)
{
	my__signal = signo;

	do_final_steps(1);

	sigchain_pop(signo);
	raise(signo);
}

static void intern_argv(int argc, const char **argv)
{
	int k;

	for (k = 0; k < argc; k++)
		argv_array_push(&my__argv, argv[k]);
}

/*
 * Collect basic startup information before cmd_main() has a chance
 * to alter the command line and before we have seen the config (to
 * know if logging is enabled).  And since the config isn't loaded
 * until cmd_main() dispatches to cmd_<command>(), we have to wait
 * and lazy-write the "cmd_start" event.
 *
 * This also implies that commands such as "help" and "version" that
 * don't need load the config won't generate any log data.
 */
static void initialize(int argc, const char **argv)
{
	my__start_time = getnanotime() / 1000;
	my__pid = getpid();
	compute_our_sid();

	intern_argv(argc, argv);

	atexit(slog_atexit);

	/*
	 * Put up backstop signal handler to ensure we get the "cmd_exit"
	 * event.  This is primarily for when the pager throws SIGPIPE
	 * when the user quits.
	 */
	sigchain_push(SIGPIPE, slog_signal);
}

int slog_wrap_main(slog_fn_main_t fn_main, int argc, const char **argv)
{
	int result;

	initialize(argc, argv);
	result = fn_main(argc, argv);
	slog_exit_code(result);

	return result;
}

void slog_set_command_name(const char *command_name)
{
	/*
	 * Capture the command name even if logging is not enabled
	 * because we don't know if the config has been loaded yet by
	 * the cmd_<command>() and/or it may be too early to force a
	 * lazy load.
	 */
	if (my__command_name)
		free(my__command_name);
	my__command_name = xstrdup(command_name);
}

void slog_set_sub_command_name(const char *sub_command_name)
{
	/*
	 * Capture the sub-command name even if logging is not enabled
	 * because we don't know if the config has been loaded yet by
	 * the cmd_<command>() and/or it may be too early to force a
	 * lazy load.
	 */
	if (my__sub_command_name)
		free(my__sub_command_name);
	my__sub_command_name = xstrdup(sub_command_name);
}

int slog_is_pretty(void)
{
	return my__is_pretty;
}

int slog_exit_code(int exit_code)
{
	my__exit_time = getnanotime() / 1000;
	my__exit_code = exit_code;

	return exit_code;
}

void slog_error_message(const char *prefix, const char *fmt, va_list params)
{
	struct strbuf em = STRBUF_INIT;
	va_list copy_params;

	if (prefix && *prefix)
		strbuf_addstr(&em, prefix);

	va_copy(copy_params, params);
	strbuf_vaddf(&em, fmt, copy_params);
	va_end(copy_params);

	if (!my__errors.json.len)
		jw_array_begin(&my__errors, my__is_pretty);
	jw_array_string(&my__errors, em.buf);
	/* leave my__errors array unterminated for now */

	strbuf_release(&em);
}

int slog_want_detail_event(const char *category)
{
	return want_category(&my__detail_categories, category);
}

void slog_emit_detail_event(const char *category, const char *label,
			    const struct json_writer *data)
{
	if (!my__wrote_start_event)
		emit_start_event();

	if (!slog_want_detail_event(category))
		return;

	if (!category || !*category)
		BUG("no category for slog.detail event");
	if (!label || !*label)
		BUG("no label for slog.detail event");
	if (data && !jw_is_terminated(data))
		BUG("unterminated slog.detail data: '%s' '%s' '%s'",
		    category, label, data->json.buf);

	emit_detail_event(category, label, getnanotime(), data);
}

int slog_start_timer(const char *category, const char *name)
{
	int k;
	struct timer_data *td;

	if (!want_category(&my__timer_categories, category))
		return SLOG_UNDEFINED_TIMER_ID;
	if (!name || !*name)
		return SLOG_UNDEFINED_TIMER_ID;

	for (k = 0; k < my__timers.nr; k++) {
		td = my__timers.array[k];
		if (!strcmp(category, td->category) && !strcmp(name, td->name))
			goto start_timer;
	}

	td = xcalloc(1, sizeof(struct timer_data));
	td->category = xstrdup(category);
	td->name = xstrdup(name);
	td->min_ns = UINT64_MAX;

	ALLOC_GROW(my__timers.array, my__timers.nr + 1, my__timers.alloc);
	my__timers.array[my__timers.nr++] = td;

start_timer:
	if (td->started)
		BUG("slog.timer '%s:%s' already started",
		    td->category, td->name);

	td->start_ns = getnanotime();
	td->started = 1;

	return k;
}

static void stop_timer(struct timer_data *td)
{
	uint64_t delta_ns = getnanotime() - td->start_ns;

	td->count++;
	td->total_ns += delta_ns;
	if (delta_ns < td->min_ns)
		td->min_ns = delta_ns;
	if (delta_ns > td->max_ns)
		td->max_ns = delta_ns;
	td->started = 0;
}

void slog_stop_timer(int tid)
{
	struct timer_data *td;

	if (tid == SLOG_UNDEFINED_TIMER_ID)
		return;
	if (tid >= my__timers.nr || tid < 0)
		BUG("Invalid slog.timer id '%d'", tid);

	td = my__timers.array[tid];
	if (!td->started)
		BUG("slog.timer '%s:%s' not started", td->category, td->name);

	stop_timer(td);
}

static int sort_timers_cb(const void *a, const void *b)
{
	struct timer_data *td_a = *(struct timer_data **)a;
	struct timer_data *td_b = *(struct timer_data **)b;
	int r;

	r = strcmp(td_a->category, td_b->category);
	if (r)
		return r;
	return strcmp(td_a->name, td_b->name);
}

static void format_a_timer(struct json_writer *jw, struct timer_data *td,
			   int force_stop)
{
	jw_object_inline_begin_object(jw, td->name);
	{
		jw_object_intmax(jw, "count", td->count);
		jw_object_intmax(jw, "total_us", td->total_ns / 1000);
		if (td->count > 1) {
			uint64_t avg_ns = td->total_ns / td->count;

			jw_object_intmax(jw, "min_us", td->min_ns / 1000);
			jw_object_intmax(jw, "max_us", td->max_ns / 1000);
			jw_object_intmax(jw, "avg_us", avg_ns / 1000);
		}
		if (force_stop)
			jw_object_true(jw, "force_stop");
	}
	jw_end(jw);
}

static void format_timers(struct json_writer *jw)
{
	const char *open_category = NULL;
	int k;

	QSORT(my__timers.array, my__timers.nr, sort_timers_cb);

	for (k = 0; k < my__timers.nr; k++) {
		struct timer_data *td = my__timers.array[k];
		int force_stop = td->started;

		if (force_stop)
			stop_timer(td);

		if (!open_category) {
			jw_object_inline_begin_object(jw, td->category);
			open_category = td->category;
		}
		else if (strcmp(open_category, td->category)) {
			jw_end(jw);
			jw_object_inline_begin_object(jw, td->category);
			open_category = td->category;
		}

		format_a_timer(jw, td, force_stop);
	}

	if (open_category)
		jw_end(jw);
}

static void free_timers(void)
{
	int k;

	for (k = 0; k < my__timers.nr; k++) {
		struct timer_data *td = my__timers.array[k];

		free(td->category);
		free(td->name);
		free(td);
	}

	FREE_AND_NULL(my__timers.array);
	my__timers.nr = 0;
	my__timers.alloc = 0;
}

int slog_want_aux(const char *category)
{
	return want_category(&my__aux_categories, category);
}

static struct aux_data *find_aux_data(const char *category)
{
	struct aux_data *ad;
	int k;

	if (!slog_want_aux(category))
		return NULL;

	for (k = 0; k < my__aux_data.nr; k++) {
		ad = my__aux_data.array[k];
		if (!strcmp(category, ad->category))
			return ad;
	}

	ad = xcalloc(1, sizeof(struct aux_data));
	ad->category = xstrdup(category);

	jw_array_begin(&ad->jw, my__is_pretty);
	/* leave per-category object unterminated for now */

	ALLOC_GROW(my__aux_data.array, my__aux_data.nr + 1, my__aux_data.alloc);
	my__aux_data.array[my__aux_data.nr++] = ad;

	return ad;
}

#define add_to_aux(c, k, v, fn)						\
	do {								\
		struct aux_data *ad = find_aux_data((c));		\
		if (ad) {						\
			jw_array_inline_begin_array(&ad->jw);		\
			{						\
				jw_array_string(&ad->jw, (k));		\
				(fn)(&ad->jw, (v));			\
			}						\
			jw_end(&ad->jw);				\
		}							\
	} while (0)

void slog_aux_string(const char *category, const char *key, const char *value)
{
	add_to_aux(category, key, value, jw_array_string);
}

void slog_aux_intmax(const char *category, const char *key, intmax_t value)
{
	add_to_aux(category, key, value, jw_array_intmax);
}

void slog_aux_bool(const char *category, const char *key, int value)
{
	add_to_aux(category, key, value, jw_array_bool);
}

void slog_aux_jw(const char *category, const char *key,
		 const struct json_writer *value)
{
	add_to_aux(category, key, value, jw_array_sub_jw);
}

static void format_and_free_aux_data(struct json_writer *jw)
{
	int k;

	for (k = 0; k < my__aux_data.nr; k++) {
		struct aux_data *ad = my__aux_data.array[k];

		/* terminate per-category form */
		jw_end(&ad->jw);

		/* insert per-category form into containing "aux" form */
		jw_object_sub_jw(jw, ad->category, &ad->jw);

		jw_release(&ad->jw);
		free(ad->category);
		free(ad);
	}

	FREE_AND_NULL(my__aux_data.array);
	my__aux_data.nr = 0;
	my__aux_data.alloc = 0;
}

static struct child_data *alloc_child_data(const struct child_process *cmd)
{
	struct child_data *cd = xcalloc(1, sizeof(struct child_data));

	cd->start_ns = getnanotime();
	cd->is_running = 1;
	cd->is_git_cmd = cmd->git_cmd;
	cd->use_shell = cmd->use_shell;

	jw_init(&cd->jw_argv);

	jw_array_begin(&cd->jw_argv, my__is_pretty);
	{
		jw_array_argv(&cd->jw_argv, cmd->argv);
	}
	jw_end(&cd->jw_argv);

	return cd;
}

static int insert_child_data(struct child_data *cd)
{
	int child_id = my__child_data.nr;

	ALLOC_GROW(my__child_data.array, my__child_data.nr + 1,
		   my__child_data.alloc);
	my__child_data.array[my__child_data.nr++] = cd;

	return child_id;
}

int slog_child_starting(const struct child_process *cmd)
{
	struct child_data *cd;
	int child_id;

	if (!slog_is_enabled())
		return SLOG_UNDEFINED_CHILD_ID;

	/*
	 * If we have not yet written a cmd_start event (and even if
	 * we do not emit this child_start event), force the cmd_start
	 * event now so that it appears in the log before any events
	 * that the child process itself emits.
	 */
	if (!my__wrote_start_event)
		emit_start_event();

	cd = alloc_child_data(cmd);
	child_id = insert_child_data(cd);

	/* build data portion for a "detail" event */
	if (slog_want_detail_event("child")) {
		struct json_writer jw_data = JSON_WRITER_INIT;

		jw_object_begin(&jw_data, my__is_pretty);
		{
			jw_object_intmax(&jw_data, "child_id", child_id);
			jw_object_bool(&jw_data, "git_cmd", cd->is_git_cmd);
			jw_object_bool(&jw_data, "use_shell", cd->use_shell);
			jw_object_sub_jw(&jw_data, "child_argv", &cd->jw_argv);
		}
		jw_end(&jw_data);

		emit_detail_event("child", "child_starting", cd->start_ns,
				  &jw_data);
		jw_release(&jw_data);
	}

	return child_id;
}

void slog_child_ended(int child_id, int child_pid, int child_exit_code)
{
	struct child_data *cd;

	if (!slog_is_enabled())
		return;
	if (child_id == SLOG_UNDEFINED_CHILD_ID)
		return;
	if (child_id >= my__child_data.nr || child_id < 0)
		BUG("Invalid slog.child id '%d'", child_id);

	cd = my__child_data.array[child_id];
	if (!cd->is_running)
		BUG("slog.child '%d' already stopped", child_id);

	cd->end_ns = getnanotime();
	cd->is_running = 0;

	/* build data portion for a "detail" event */
	if (slog_want_detail_event("child")) {
		struct json_writer jw_data = JSON_WRITER_INIT;

		jw_object_begin(&jw_data, my__is_pretty);
		{
			jw_object_intmax(&jw_data, "child_id", child_id);
			jw_object_bool(&jw_data, "git_cmd", cd->is_git_cmd);
			jw_object_bool(&jw_data, "use_shell", cd->use_shell);
			jw_object_sub_jw(&jw_data, "child_argv", &cd->jw_argv);

			jw_object_intmax(&jw_data, "child_pid", child_pid);
			jw_object_intmax(&jw_data, "child_exit_code",
					 child_exit_code);
			jw_object_intmax(&jw_data, "child_elapsed_us",
					 (cd->end_ns - cd->start_ns) / 1000);
		}
		jw_end(&jw_data);

		emit_detail_event("child", "child_ended", cd->end_ns, &jw_data);
		jw_release(&jw_data);
	}
}

static void free_children(void)
{
	int k;

	for (k = 0; k < my__child_data.nr; k++) {
		struct child_data *cd = my__child_data.array[k];

		jw_release(&cd->jw_argv);
		free(cd);
	}

	FREE_AND_NULL(my__child_data.array);
	my__child_data.nr = 0;
	my__child_data.alloc = 0;
}

#endif
