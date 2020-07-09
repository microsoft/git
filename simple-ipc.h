#ifndef GIT_SIMPLE_IPC_H
#define GIT_SIMPLE_IPC_H

/*
 * See Documentation/technical/api-simple-ipc.txt
 */

#if defined(GIT_WINDOWS_NATIVE) || !defined(NO_UNIX_SOCKETS)
#define SUPPORTS_SIMPLE_IPC
#endif

#ifdef SUPPORTS_SIMPLE_IPC

enum ipc_active_state {
	/*
	 * The pipe/socket exists and the daemon is waiting for connections.
	 */
	IPC_STATE__LISTENING = 0,

	/*
	 * The pipe/socket exists, but the daemon is not listening.
	 * Perhaps it is very busy.
	 * Perhaps the daemon died without deleting the path.
	 * Perhaps it is shutting down and draining existing clients.
	 * Perhaps it is dead, but other clients are lingering and
	 * still holding a reference to the pathname.
	 */
	IPC_STATE__NOT_LISTENING,

	/*
	 * The requested pathname is bogus and no amount of retries
	 * will fix that.
	 */
	IPC_STATE__INVALID_PATH,

	/*
	 * The requested pathname is not found.  This usually means
	 * that there is no daemon present.
	 */
	IPC_STATE__PATH_NOT_FOUND,

	IPC_STATE__OTHER_ERROR,
};

struct ipc_client_connect_options {
	/*
	 * Spin under timeout if the server is running but can't
	 * accept our connection yet.  This should always be set
	 * unless you just want to poke the server and see if it
	 * is alive.
	 */
	unsigned int wait_if_busy :1;

	/*
	 * Spin under timeout if the pipe/socket is not yet present
	 * on the file system.  This is useful if we just started
	 * the service and need to wait for it to become ready.
	 */
	unsigned int wait_if_not_found :1;
};

#define IPC_CLIENT_CONNECT_OPTIONS_INIT { \
	.wait_if_busy = 0, \
	.wait_if_not_found = 0, \
}

/*
 * Determine if a server is listening on this named pipe or socket using
 * platform-specific logic.  This might just probe the filesystem or it
 * might make a trivial connection to the server using this pathname.
 */
enum ipc_active_state ipc_get_active_state(const char *path);

/*
 * Try to connect to the daemon on the named pipe or socket.
 *
 * Returns IPC_STATE__LISTENING (and an fd) when connected.
 *
 * Otherwise, returns info to help decide whether to retry or to
 * spawn/respawn the server.
 */
enum ipc_active_state ipc_client_try_connect(
	const char *path,
	const struct ipc_client_connect_options *options,
	int *pfd);

/*
 * Used by the client to synchronously send and receive a message with
 * the server on the provided fd.
 *
 * Returns 0 when successful.
 *
 * Calls error() and returns non-zero otherwise.
 */
int ipc_client_send_command_to_fd(int fd, const char *message,
				  struct strbuf *answer);

/*
 * Used by the client to synchronously connect and send and receive a
 * message to the server listening at the given path.
 *
 * Returns 0 when successful.
 *
 * Calls error() and returns non-zero otherwise.
 */
int ipc_client_send_command(const char *path,
			    const struct ipc_client_connect_options *options,
			    const char *message, struct strbuf *answer);

#endif /* SUPPORTS_SIMPLE_IPC */
#endif /* GIT_SIMPLE_IPC_H */
