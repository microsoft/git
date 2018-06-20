#include "cache.h"
#include "config.h"
#include "version.h"
#include "json-writer.h"
#include "sigchain.h"
#include "argv-array.h"

#if !defined(STRUCTURED_LOGGING)
/*
 * Structured logging is not available.
 * Stub out all API routines.
 */

#else

#define SLOG_VERSION 0

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
	}
	jw_end(&jw);

	emit_event(&jw, "cmd_exit");
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

#endif
