#include "cache.h"
#include "simple-ipc.h"
#include "strbuf.h"
#include "pkt-line.h"
#include "thread-utils.h"

#ifndef NO_UNIX_SOCKETS

#include "unix-socket.h"

/*
 * Write message with optional flush to a pipe with SIGPIPE disabled
 * (so that we get EPIPE from write() rather than an actual signal).
 *
 * We would like to use sigchain_push() and _pop() to control SIGPIPE
 * around our IO calls, but it is not thread safe.
 * [] It uses a global stack of handler frames.
 * [] It uses ALLOC_GROW() to resize it.
 * [] Finally, according to the `signal(2)` man-page:
 *    "The effects of `signal()` in a multithreaded process are unspecified."
 *
 * TODO This is not the right file (or name) for this function, but there
 * TODO are several issues that need to be discussed before we find a
 * TODO permanent home for it.
 */
static int write_packetized_from_buf_with_sigpipe_thread_blocked(
	const char *src_in, size_t len, int fd_out,
	int flush_at_end)
{
	sigset_t old_set;
	sigset_t new_set;
	int saved_errno;
	int ret;

	sigemptyset(&old_set);
	sigemptyset(&new_set);
	sigaddset(&new_set, SIGPIPE);

	pthread_sigmask(SIG_BLOCK, &new_set, &old_set);

	ret = write_packetized_from_buf(src_in, len, fd_out, flush_at_end);
	saved_errno = errno;

	pthread_sigmask(SIG_SETMASK, &old_set, NULL);

	errno = saved_errno;
	return ret;
}

enum IPC_ACTIVE_STATE ipc_is_active(const char *path)
{
	struct stat st;

	if (lstat(path, &st) == -1) {
		switch (errno) {
		case ENOENT:
		case ENOTDIR:
			return IPC_STATE__NOT_ACTIVE;
		default:
			return IPC_STATE__INVALID_PATH;
		}
	}

	/* also complain if a plain file is in the way */
	if ((st.st_mode & S_IFMT) != S_IFSOCK)
		return IPC_STATE__INVALID_PATH;

	/*
	 * If we have have valid socket at that path then we have to
	 * assume that there is a server running somewhere and listening.
	 */
	return IPC_STATE__ACTIVE;
}

static int client_write_and_read(const char *path, int fd,
				 const char *message, struct strbuf *answer)
{
	if (write_packetized_from_buf_with_sigpipe_thread_blocked(
		    message, strlen(message), fd, 1) < 0)
		return error_errno(_("could not send IPC to '%s'"), path);

	if (!answer)
		return 0;

	if (read_packetized_to_strbuf(fd, answer, PACKET_READ_NEVER_DIE) < 0)
		return error_errno(_("could not read IPC response from '%s'"),
				   path);

	return 0;
}

/*
 * If the server if very busy, we may not get a connection the first time.
 */
static int connect_to_server(const char *path, int timeout_ms)
{
	int wait_ms = 50;
	int k;

	for (k = 0; k < timeout_ms; k += wait_ms) {
		int fd = unix_stream_connect(path);

		if (fd != -1)
			return fd;
		if (errno != ECONNREFUSED)
			return fd;

		/*
		 * ECONNREFUSED usually means the server is busy and cannot
		 * accept() our connection attempt.
		 */
		sleep_millisec(wait_ms);
	}

	return -1;
}

/*
 * A randomly chosen timeout value.
 */
#define MY_CONNECTION_TIMEOUT_MS (1000)

int ipc_client_send_command(const char *path, const char *message,
			    struct strbuf *answer)
{
	int fd;
	int ret;

	fd = connect_to_server(path, MY_CONNECTION_TIMEOUT_MS);
	if (fd < 0)
		return error_errno(_("could not open UDS for '%s'"),
				   path);

	ret = client_write_and_read(path, fd, message, answer);

	close(fd);
	return ret;
}

#endif /* !NO_UNIX_SOCKETS */
