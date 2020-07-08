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

/*
 * An IPC server can also be created in an asynchronous mode.  The server
 * is started in a background thread of the current process.  Control
 * immediately returns control to the caller.  Later, the caller can request
 * the server to shutdown and wait for background threads to stop.
 */

struct ipc_server_data;

int ipc_server_run_async(struct ipc_server_data **returned_server_data,
			 const char *path, int nr_threads,
			 ipc_server_application_cb *application_cb,
			 void *application_data);
int ipc_server_stop_async(struct ipc_server_data *server_data);
int ipc_server_await(struct ipc_server_data *server_data);
void ipc_server_free(struct ipc_server_data *server_data);

#endif /* SUPPORTS_SIMPLE_IPC */
#endif /* GIT_SIMPLE_IPC_H */
