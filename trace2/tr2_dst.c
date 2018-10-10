#include "cache.h"
#include "trace2/tr2_dst.h"

/*
 * This file contains "private/protected" declarations for TRACE2.
 */

void tr2_dst_trace_disable(struct tr2_dst *dst)
{
	if (dst->need_close)
		close(dst->fd);
	dst->fd = 0;
	dst->initialized = 1;
	dst->need_close = 0;
}

int tr2_dst_get_trace_fd(struct tr2_dst *dst)
{
	const char *trace;

	/* don't open twice */
	if (dst->initialized)
		return dst->fd;

	trace = getenv(dst->env_var_name);

	if (!trace || !strcmp(trace, "") ||
	    !strcmp(trace, "0") || !strcasecmp(trace, "false"))
		dst->fd = 0;
	else if (!strcmp(trace, "1") || !strcasecmp(trace, "true"))
		dst->fd = STDERR_FILENO;
	else if (strlen(trace) == 1 && isdigit(*trace))
		dst->fd = atoi(trace);
	else if (is_absolute_path(trace)) {
		int fd = open(trace, O_WRONLY | O_APPEND | O_CREAT, 0666);
		if (fd == -1) {
			warning("could not open '%s' for tracing: %s",
				trace, strerror(errno));
			tr2_dst_trace_disable(dst);
		} else {
			dst->fd = fd;
			dst->need_close = 1;
		}
	} else {
		warning("unknown trace value for '%s': %s\n"
			"         If you want to trace into a file, then please set %s\n"
			"         to an absolute pathname (starting with /)",
			dst->env_var_name, trace, dst->env_var_name);
		tr2_dst_trace_disable(dst);
	}

	dst->initialized = 1;
	return dst->fd;
}

int tr2_dst_trace_want(struct tr2_dst *dst)
{
	return !!tr2_dst_get_trace_fd(dst);
}

void tr2_dst_write_line(struct tr2_dst *dst, struct strbuf *buf_line)
{
	strbuf_complete_line(buf_line); /* ensure final NL on buffer */

	/*
	 * We do not use write_in_full() because we do not want
	 * a short-write to try again.  We are using O_APPEND mode
	 * files and the kernel handles the atomic seek+write. If
	 * another thread or git process is concurrently writing to
	 * this fd or file, our remainder-write may not be contiguous
	 * with our initial write of this message.  And that will
	 * confuse readers.  So just don't bother.
	 *
	 * It is assumed that TRACE2 messages are short enough that
	 * the system can write them in 1 attempt and we won't see
	 * a short-write.
	 *
	 * If we get an IO error, just close the trace dst.
	 */

	if (write(tr2_dst_get_trace_fd(dst),
		  buf_line->buf, buf_line->len) < 0) {
		warning("unable to write trace for '%s': %s",
			dst->env_var_name, strerror(errno));
		tr2_dst_trace_disable(dst);
	}
}
