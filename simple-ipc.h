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

struct ipc_server_reply_data;

typedef int (ipc_server_reply_cb)(struct ipc_server_reply_data *,
				  const char *response,
				  size_t response_len);

/*
 * Prototype for an application-supplied callback to process incoming
 * client IPC messages and compose a reply.  The `application_cb` should
 * use the provided `reply_cb` and `reply_data` to send an IPC response
 * back to the client.  The `reply_cb` callback can be called multiple
 * times for chunking purposes.  A reply message is optional and may be
 * omitted if not necessary for the application.
 *
 * The return value from the application callback is ignored.
 * The value `SIMPLE_IPC_QUIT` can be used to shutdown the server.
 */
typedef int (ipc_server_application_cb)(void *application_data,
					const char *request,
					ipc_server_reply_cb *reply_cb,
					struct ipc_server_reply_data *reply_data);

#define SIMPLE_IPC_QUIT -2

/*
 * Run an IPC server instance in the current process.  It does not return
 * until the IPC server has either shutdown or had an unrecoverable error.
 *
 * The IPC server handles incoming IPC messages from client processes and
 * may use one or more background threads as necessary.
 *
 * Returns 0 if successful.
 *
 * When a client IPC message is received, the `application_cb` will be called
 * (possibly on a random thread) to handle the message and optionally compose
 * a reply message.
 */
int ipc_server_run(const char *path, int nr_threads,
		   ipc_server_application_cb *application_cb,
		   void *application_data);

#endif /* SUPPORTS_SIMPLE_IPC */
#endif /* GIT_SIMPLE_IPC_H */
