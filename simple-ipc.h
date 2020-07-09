#ifndef GIT_SIMPLE_IPC_H
#define GIT_SIMPLE_IPC_H

/*
 * See Documentation/technical/api-simple-ipc.txt
 */

#if defined(GIT_WINDOWS_NATIVE) || !defined(NO_UNIX_SOCKETS)
#define SUPPORTS_SIMPLE_IPC
#endif

#ifdef SUPPORTS_SIMPLE_IPC

enum IPC_ACTIVE_STATE {
	IPC_STATE__ACTIVE = 0,
	IPC_STATE__NOT_ACTIVE = 1,
	IPC_STATE__INVALID_PATH = 2,
};

/*
 * Inspect the filesystem to determine if a server is running on this
 * named pipe or socket (without actually sending a message) by testing
 * the availability and/or existence of the pipe or socket.
 */
enum IPC_ACTIVE_STATE ipc_is_active(const char *path);

/*
 * Used by the client to synchronously send a message to the server and
 * receive a response.
 *
 * Returns 0 when successful.
 *
 * Calls error() and returns non-zero otherwise.
 */
int ipc_client_send_command(const char *path, const char *message,
			    struct strbuf *answer);

#endif /* SUPPORTS_SIMPLE_IPC */
#endif /* GIT_SIMPLE_IPC_H */
