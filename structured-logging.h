#ifndef STRUCTURED_LOGGING_H
#define STRUCTURED_LOGGING_H

struct json_writer;
struct child_process;

typedef int (*slog_fn_main_t)(int, const char **);

#define SLOG_UNDEFINED_TIMER_ID (-1)
#define SLOG_UNDEFINED_CHILD_ID (-1)

#if !defined(STRUCTURED_LOGGING)
/*
 * Structured logging is not available.
 * Stub out all API routines.
 */
#define slog_is_available() (0)
#define slog_default_config(k, v) (0)
#define slog_wrap_main(real_cmd_main, argc, argv) ((real_cmd_main)((argc), (argv)))
#define slog_set_command_name(n) do { } while (0)
#define slog_set_sub_command_name(n) do { } while (0)
#define slog_is_enabled() (0)
#define slog_is_pretty() (0)
#define slog_exit_code(exit_code) (exit_code)
#define slog_error_message(prefix, fmt, params) do { } while (0)
#define slog_want_detail_event(category) (0)
#define slog_emit_detail_event(category, label, data) do { } while (0)
#define slog_start_timer(category, name) (SLOG_UNDEFINED_TIMER_ID)
static inline void slog_stop_timer(int tid) { };
#define slog_want_aux(c) (0)
#define slog_aux_string(c, k, v) do { } while (0)
#define slog_aux_intmax(c, k, v) do { } while (0)
#define slog_aux_bool(c, k, v) do { } while (0)
#define slog_aux_jw(c, k, v) do { } while (0)
#define slog_child_starting(cmd) (SLOG_UNDEFINED_CHILD_ID)
#define slog_child_ended(i, p, ec) do { } while (0)
#define slog_set_config_data_string(k, v) do { } while (0)
#define slog_set_config_data_intmax(k, v) do { } while (0)

#else

/*
 * Is structured logging available (compiled-in)?
 */
#define slog_is_available() (1)

/*
 * Process "slog.*" config settings.
 */
int slog_default_config(const char *key, const char *value);

/*
 * Wrapper for the "real" cmd_main().  Initialize structured logging if
 * enabled, run the given real_cmd_main(), and capture the return value.
 *
 * Note:  common-main.c is shared by many top-level commands.
 * common-main.c:main() does common process setup before calling
 * the version of cmd_main() found in the executable.  Some commands
 * SHOULD NOT do logging (such as t/helper/test-tool).  Ones that do
 * need some common initialization/teardown.
 *
 * Use this function for any top-level command that should do logging.
 *
 * Usage:
 *
 * static int real_cmd_main(int argc, const char **argv)
 * {
 *     ....the actual code for the command....
 * }
 *
 * int cmd_main(int argc, const char **argv)
 * {
 *     return slog_wrap_main(real_cmd_main, argc, argv);
 * }
 * 
 *
 * See git.c for an example.
 */ 
int slog_wrap_main(slog_fn_main_t real_cmd_main, int argc, const char **argv);

/*
 * Record a canonical command name and optional sub-command name for the
 * current process.  For example, "checkout" and "switch-branch".
 */
void slog_set_command_name(const char *name);
void slog_set_sub_command_name(const char *name);

/*
 * Is structured logging enabled?
 */
int slog_is_enabled(void);

/*
 * Is JSON pretty-printing enabled?
 */
int slog_is_pretty(void);

/*
 * Register the process exit code with the structured logging layer
 * and return it.  This value will appear in the final "cmd_exit" event.
 *
 * Use this to wrap all calls to exit().
 * Use this before returning in main().
 */
int slog_exit_code(int exit_code);

/*
 * Append formatted error message to the structured log result.
 * Messages from this will appear in the final "cmd_exit" event.
 */
void slog_error_message(const char *prefix, const char *fmt, va_list params);

/*
 * Is detail logging enabled for this category?
 */
int slog_want_detail_event(const char *category);

/*
 * Write a detail event.
 */

void slog_emit_detail_event(const char *category, const char *label,
			    const struct json_writer *data);

/*
 * Define and start or restart a structured logging timer.  Stats for the
 * timer will be added to the "cmd_exit" event. Use a timer when you are
 * interested in the net time of an operation (such as part of a computation
 * in a loop) but don't want a detail event for each iteration.
 *
 * Returns a timer id.
 */
int slog_start_timer(const char *category, const char *name);

/*
 * Stop the timer.
 */
void slog_stop_timer(int tid);

/*
 * Add arbitrary extra key/value data to the "cmd_exit" event.
 * These fields will appear under the "aux" object.  This is
 * intended for "interesting" config values or repo stats, such
 * as the size of the index.
 *
 * These key/value pairs are written as an array-pair rather than
 * an object/value because the keys may be repeated.
 */
int slog_want_aux(const char *category);
void slog_aux_string(const char *category, const char *key, const char *value);
void slog_aux_intmax(const char *category, const char *key, intmax_t value);
void slog_aux_bool(const char *category, const char *key, int value);
void slog_aux_jw(const char *category, const char *key,
		 const struct json_writer *value);

/*
 * Emit a detail event of category "child" and label "child_starting"
 * or "child_ending" with information about the child process.  Note
 * that this is in addition to any events that the child process itself
 * generates.
 *
 * Set "slog.detail" to true or contain "child" to get these events.
 */
int slog_child_starting(const struct child_process *cmd);
void slog_child_ended(int child_id, int child_pid, int child_exit_code);

/*
 * Add an important config key/value pair to the "cmd_event".  Keys
 * are assumed to be of the form <group>.<name>, such as "slog.path".
 * The pair will appear under the "config" object in the resulting JSON
 * as "config.<group>.<name>:<value>".
 *
 * This should only be used for important config settings.
 */
void slog_set_config_data_string(const char *key, const char *value);
void slog_set_config_data_intmax(const char *key, intmax_t value);

#endif /* STRUCTURED_LOGGING */
#endif /* STRUCTURED_LOGGING_H */
