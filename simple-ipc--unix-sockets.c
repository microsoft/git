#include "cache.h"
#include "simple-ipc.h"
#include "strbuf.h"
#include "pkt-line.h"
#include "thread-utils.h"

#ifndef NO_UNIX_SOCKETS

#include "unix-socket.h"

enum ipc_active_state ipc_get_active_state(const char *path)
{
	enum ipc_active_state state = IPC_STATE__OTHER_ERROR;
	struct ipc_client_connect_options options
		= IPC_CLIENT_CONNECT_OPTIONS_INIT;
	struct stat st;
	int fd_test = -1;

	options.wait_if_busy = 0;
	options.wait_if_not_found = 0;

	if (lstat(path, &st) == -1) {
		switch (errno) {
		case ENOENT:
		case ENOTDIR:
			return IPC_STATE__NOT_LISTENING;
		default:
			return IPC_STATE__INVALID_PATH;
		}
	}

	/* also complain if a plain file is in the way */
	if ((st.st_mode & S_IFMT) != S_IFSOCK)
		return IPC_STATE__INVALID_PATH;

	/*
	 * Just because the filesystem has a S_IFSOCK type inode
	 * at `path`, doesn't mean it that there is a server listening.
	 * Ping it to be sure.
	 */
	state = ipc_client_try_connect(path, &options, &fd_test);
	close(fd_test);

	return state;
}

/*
 * This value was chosen at random.
 */
#define WAIT_STEP_MS (50)

/*
 * Try to connect to the server.  If the server is just starting up or
 * is very busy, we may not get a connection the first time.
 */
static enum ipc_active_state connect_to_server(
	const char *path,
	int timeout_ms,
	const struct ipc_client_connect_options *options,
	int *pfd)
{
	int wait_ms = 50;
	int k;

	*pfd = -1;

	for (k = 0; k < timeout_ms; k += wait_ms) {
		int fd = unix_stream_connect(path);

		if (fd != -1) {
			*pfd = fd;
			return IPC_STATE__LISTENING;
		}

		if (errno == ENOENT) {
			if (!options->wait_if_not_found)
				return IPC_STATE__PATH_NOT_FOUND;

			goto sleep_and_try_again;
		}

		if (errno == ETIMEDOUT) {
			if (!options->wait_if_busy)
				return IPC_STATE__NOT_LISTENING;

			goto sleep_and_try_again;
		}

		if (errno == ECONNREFUSED) {
			if (!options->wait_if_busy)
				return IPC_STATE__NOT_LISTENING;

			goto sleep_and_try_again;
		}

		return IPC_STATE__OTHER_ERROR;

	sleep_and_try_again:
		sleep_millisec(wait_ms);
	}

	return IPC_STATE__NOT_LISTENING;
}

/*
 * A randomly chosen timeout value.
 */
#define MY_CONNECTION_TIMEOUT_MS (1000)

enum ipc_active_state ipc_client_try_connect(
	const char *path,
	const struct ipc_client_connect_options *options,
	int *pfd)
{
	enum ipc_active_state state = IPC_STATE__OTHER_ERROR;

	*pfd = -1;

	trace2_region_enter("ipc-client", "try-connect", NULL);
	trace2_data_string("ipc-client", NULL, "try-connect/path", path);

	state = connect_to_server(path, MY_CONNECTION_TIMEOUT_MS,
				  options, pfd);

	trace2_data_intmax("ipc-client", NULL, "try-connect/state",
			   (intmax_t)state);
	trace2_region_leave("ipc-client", "try-connect", NULL);
	return state;
}

int ipc_client_send_command_to_fd(int fd, const char *message,
				  struct strbuf *answer)
{
	int ret = 0;

	strbuf_setlen(answer, 0);

	trace2_region_enter("ipc-client", "send-command", NULL);

	if (write_packetized_from_buf(message, strlen(message), fd, 1) < 0) {
		ret = error(_("could not send IPC command"));
		goto done;
	}

	if (read_packetized_to_strbuf(fd, answer, PACKET_READ_NEVER_DIE) < 0) {
		ret = error(_("could not read IPC response"));
		goto done;
	}

done:
	trace2_region_leave("ipc-client", "send-command", NULL);
	return ret;
}

int ipc_client_send_command(const char *path,
			    const struct ipc_client_connect_options *options,
			    const char *message, struct strbuf *answer)
{
	int fd;
	int ret = -1;
	enum ipc_active_state state;

	state = ipc_client_try_connect(path, options, &fd);

	if (state != IPC_STATE__LISTENING)
		return ret;

	ret = ipc_client_send_command_to_fd(fd, message, answer);
	close(fd);
	return ret;
}

#endif /* !NO_UNIX_SOCKETS */
