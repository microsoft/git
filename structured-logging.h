#ifndef STRUCTURED_LOGGING_H
#define STRUCTURED_LOGGING_H

typedef int (*slog_fn_main_t)(int, const char **);

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

#endif /* STRUCTURED_LOGGING */
#endif /* STRUCTURED_LOGGING_H */
