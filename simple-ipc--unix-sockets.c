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

/*
 * TODO Similarly, this function needs to be moved too.
 */
static int packet_flush_gently_with_sigpipe_thread_blocked(int fd)
{
	sigset_t old_set;
	sigset_t new_set;
	int saved_errno;
	int ret;

	sigemptyset(&old_set);
	sigemptyset(&new_set);
	sigaddset(&new_set, SIGPIPE);

	pthread_sigmask(SIG_BLOCK, &new_set, &old_set);

	ret = packet_flush_gently(fd);
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

static struct string_list listener_paths = STRING_LIST_INIT_DUP;
static int atexit_registered;

static void unlink_listener_path(void)
{
	int i;

	for (i = 0; i < listener_paths.nr; i++)
		unlink(listener_paths.items[i].string);

	string_list_clear(&listener_paths, 0);
}

static void register_atexit(const char *path)
{
	if (!atexit_registered) {
		atexit(unlink_listener_path);
		atexit_registered = 1;
	}

	string_list_append(&listener_paths, path);
}

static int set_socket_blocking_flag(int fd, int make_nonblocking)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);

	if (flags < 0)
		return -1;

	if (make_nonblocking)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	return fcntl(fd, F_SETFL, flags);
}

static const char *MAGIC_SERVER_REPLY_DATA = "T_Reply_T";
static const char *MAGIC_WORKER_THREAD_DATA = "T_Worker_T";
static const char *MAGIC_ACCEPT_THREAD_DATA = "T_Accept_T";
static const char *MAGIC_SERVER_DATA = "T_Server_T";

struct ipc_server_reply_data {
	const char *magic;
	int fd;
	struct ipc_worker_thread_data *worker_thread_data;
};

struct ipc_worker_thread_data {
	const char *magic;
	struct ipc_worker_thread_data *next_thread;
	struct ipc_server_data *server_data;
	pthread_t pthread_id;
};

struct ipc_accept_thread_data {
	const char *magic;
	struct ipc_server_data *server_data;
	int fd_listen;
	int fd_send_shutdown;
	int fd_wait_shutdown;
	pthread_t pthread_id;
};

/*
 * With unix-sockets, the conceptual "ipc-server" is implemented as a single
 * controller "accept-thread" thread and a pool of "worker-thread" threads.
 * The former does the usual `accept()` loop and dispatches connections
 * to an idle worker thread.  The worker threads wait in an idle loop for
 * a new connection, communicate with the client and relay data to/from
 * the `application_cb` and then wait for another connection from the
 * server thread.  This avoids the overhead of constantly creating and
 * destroying threads.
 */
struct ipc_server_data {
	const char *magic;
	ipc_server_application_cb *application_cb;
	void *application_data;
	struct strbuf buf_path;

	struct ipc_accept_thread_data *accept_thread;
	struct ipc_worker_thread_data *worker_thread_list;

	pthread_mutex_t work_available_mutex;
	pthread_cond_t work_available_cond;

	/*
	 * Accepted but not yet processed client connections are kept
	 * in a circular buffer FIFO.  The queue is empty when the
	 * positions are equal.
	 */
	int *fifo_fds;
	int queue_size;
	int back_pos;
	int front_pos;

	int shutdown_requested;
	int is_stopped;
};

/*
 * Remove and return the oldest queued connection.
 *
 * Returns -1 if empty.
 */
static int fifo_dequeue(struct ipc_server_data *server_data)
{
	/* ASSERT holding mutex */

	int fd;

	if (server_data->back_pos == server_data->front_pos)
		return -1;

	fd = server_data->fifo_fds[server_data->front_pos];
	server_data->fifo_fds[server_data->front_pos] = -1;

	server_data->front_pos++;
	if (server_data->front_pos == server_data->queue_size)
		server_data->front_pos = 0;

	return fd;
}

/*
 * Push a new fd onto the back of the queue.
 *
 * Drop it and return -1 if queue is already full.
 */
static int fifo_enqueue(struct ipc_server_data *server_data, int fd)
{
	/* ASSERT holding mutex */

	int next_back_pos;

	next_back_pos = server_data->back_pos + 1;
	if (next_back_pos == server_data->queue_size)
		next_back_pos = 0;

	if (next_back_pos == server_data->front_pos) {
//		trace2_printf("XXX: queue full %d", fd);
		close(fd);
		return -1;
	}

	server_data->fifo_fds[server_data->back_pos] = fd;
	server_data->back_pos = next_back_pos;

	return fd;
}

/*
 * Wait for a connection to be queued to the FIFO and return it.
 *
 * Returns -1 if someone has already requested a shutdown.
 */
static int worker_thread__wait_for_connection(
	struct ipc_worker_thread_data *worker_thread_data)
{
	/* ASSERT NOT holding mutex */

	struct ipc_server_data *server_data = worker_thread_data->server_data;
	int fd = -1;

	pthread_mutex_lock(&server_data->work_available_mutex);
	while (1) {
		if (server_data->shutdown_requested)
			break;

		fd = fifo_dequeue(server_data);
		if (fd >= 0)
			break;

		pthread_cond_wait(&server_data->work_available_cond,
				  &server_data->work_available_mutex);
	}
	pthread_mutex_unlock(&server_data->work_available_mutex);

	return fd;
}

static ipc_server_reply_cb do_io_reply;

/*
 * Relay application's response message to the client process.
 * (We do not flush at this point because we allow the caller
 * to chunk data to the client thru us.)
 */
static int do_io_reply(struct ipc_server_reply_data *reply_data,
		       const char *response, size_t response_len)
{
	if (reply_data->magic != MAGIC_SERVER_REPLY_DATA)
		BUG("reply_cb called with wrong instance data");

	return write_packetized_from_buf_with_sigpipe_thread_blocked(
		response, response_len, reply_data->fd, 0);
}

/*
 * Receive the request/command from the client and pass it to the
 * registered request-callback.  The request-callback will compose
 * a response and call our reply-callback to send it to the client.
 */
static int worker_thread__do_io(
	struct ipc_worker_thread_data *worker_thread_data,
	int fd)
{
	/* ASSERT NOT holding lock */

	struct strbuf buf = STRBUF_INIT;
	struct ipc_server_reply_data reply_data;
	int ret = 0;

	reply_data.magic = MAGIC_SERVER_REPLY_DATA;
	reply_data.worker_thread_data = worker_thread_data;

	reply_data.fd = fd;

	ret = read_packetized_to_strbuf(reply_data.fd, &buf,
					PACKET_READ_NEVER_DIE);
	if (ret >= 0) {
//		trace2_printf("simple-ipc: %s", buf.buf);

		ret = worker_thread_data->server_data->application_cb(
			worker_thread_data->server_data->application_data,
			buf.buf, do_io_reply, &reply_data);

		packet_flush_gently_with_sigpipe_thread_blocked(reply_data.fd);
	}
	else {
		/*
		 * The client probably disconnected/shutdown before it
		 * could send a well-formed message.  Ignore it.
		 */
//		trace2_printf("ipc-server[%s]: read_packetized failed",
//			      worker_thread_data->server_data->buf_path.buf);
	}

	strbuf_release(&buf);
	close(reply_data.fd);

	return ret;
}

/*
 * Thread proc for an IPC worker thread.  It handles a series of
 * connections from clients.  It pulls the next fd from the queue
 * processes it, and then waits for the next client.
 */
static void *worker_thread_proc(void *_worker_thread_data)
{
	struct ipc_worker_thread_data *worker_thread_data = _worker_thread_data;
	struct ipc_server_data *server_data = worker_thread_data->server_data;
	int ret;

	trace2_thread_start("ipc-worker");

	while (1) {
		int fd = worker_thread__wait_for_connection(worker_thread_data);

		if (fd == -1)
			break; /* in shutdown */

		ret = worker_thread__do_io(worker_thread_data, fd);

		if (ret == SIMPLE_IPC_QUIT) {
			/* The application told us to shutdown. */
			ipc_server_stop_async(server_data);
			break;
		}
	}

	trace2_thread_exit();
	return NULL;
}

/*
 * Accept a new client connection on our socket.  This uses non-blocking
 * IO so that we can also wait for shutdown requests on our socket-pair
 * without actually spinning on a timeout.
 */
static int accept_thread__wait_for_connection(
	struct ipc_accept_thread_data *accept_thread_data)
{
	struct pollfd pollfd[2];
	int result;

	while (1) {
		pollfd[0].fd = accept_thread_data->fd_wait_shutdown;
		pollfd[0].events = POLLIN;

		pollfd[1].fd = accept_thread_data->fd_listen;
		pollfd[1].events = POLLIN;

		result = poll(pollfd, 2, -1);
		if (result < 0) {
			if (errno == EINTR)
				continue;
			return result;
		}
		if (result == 0) /* a timeout */
			continue;

		if (pollfd[0].revents == POLLIN) {
			/* shutdown message queued to socketpair */
			return -1;
		}

		if (pollfd[1].revents == POLLIN) {
			/* a connection is available on fd_listen */

			int client_fd = accept(accept_thread_data->fd_listen,
					       NULL, NULL);
			if (client_fd >= 0)
				return client_fd;

			/*
			 * An error here is unlikely -- it probably
			 * indicates that the connecting process has
			 * already dropped the connection.
			 */
			continue;
		}

		BUG("unandled poll result errno=%d r[0]=%d r[1]=%d",
		    errno, pollfd[0].revents, pollfd[1].revents);
	}
}

/*
 * Thread proc for the IPC server "accept thread".  This waits for
 * an incoming socket connection, appends it to the queue of available
 * connections, and notifies a worker thread to process it.
 */
static void *accept_thread_proc(void *_accept_thread_data)
{
	struct ipc_accept_thread_data *accept_thread_data = _accept_thread_data;
	struct ipc_server_data *server_data = accept_thread_data->server_data;

	trace2_thread_start("ipc-accept");

	while (1) {
		int client_fd = accept_thread__wait_for_connection(
			accept_thread_data);

		pthread_mutex_lock(&server_data->work_available_mutex);
		if (server_data->shutdown_requested) {
			pthread_mutex_unlock(&server_data->work_available_mutex);
			if (client_fd >= 0)
				close(client_fd);
			break;
		}

		if (client_fd < 0) {
			/* ignore transient accept() errors */
		}
		else {
			fifo_enqueue(server_data, client_fd);
			// TODO We are about to add one fd to the fifo, so
			// TODO we should only need to wake up one sleeping
			// TODO worker.  Broadcasting seems overkill here.
			pthread_cond_broadcast(&server_data->work_available_cond);
		}
		pthread_mutex_unlock(&server_data->work_available_mutex);
	}

	trace2_thread_exit();
	return NULL;
}

/*
 * We can't predict the connection arrival rate relative to the worker
 * processing rate, therefore we allow the "accept-thread" to queue up
 * a few connections for each thread (in addition to whatever
 * buffering the kernel gives us).
 *
 * The FIFO queue size is set to a multiple of the worker pool size.
 */
#define FIFO_SCALE (5)

/*
 * Start IPC server in a pool of background threads.
 */
int ipc_server_run_async(struct ipc_server_data **returned_server_data,
			 const char *path, int nr_threads,
			 ipc_server_application_cb *application_cb,
			 void *application_data)
{
	struct ipc_server_data *server_data;
	int fd_listen;
	int sv[2];
	int k;
	enum IPC_ACTIVE_STATE state;

	*returned_server_data = NULL;

	state = ipc_is_active(path);
	switch (state) {
	case IPC_STATE__ACTIVE:
		return error(_("IPC server already running on '%s'"), path);

	default:
	case IPC_STATE__NOT_ACTIVE:
	case IPC_STATE__INVALID_PATH:
		break;
	}

	fd_listen = unix_stream_listen(path);
	if (fd_listen < 0)
		return error_errno(_("could not set up socket for '%s'"), path);
	if (set_socket_blocking_flag(fd_listen, 1)) {
		int saved_errno = errno;
		close(fd_listen);
		errno = saved_errno;
		return error_errno(_("could not set up socket for '%s'"), path);
	}

	/*
	 * Create a socketpair and set sv[1] to non-blocking.  This will used to
	 * send a shutdown message to the accept-thread and allows the accept-thread
	 * to wait on EITHER a client connection or a shutdown request without
	 * spinning.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		int saved_errno = errno;
		close(fd_listen);
		errno = saved_errno;
		return error_errno(_("could not set up socketpair for '%s'"), path);
	}
	if (set_socket_blocking_flag(sv[1], 1)) {
		int saved_errno = errno;
		close(fd_listen);
		close(sv[0]);
		close(sv[1]);
		errno = saved_errno;
		return error_errno(_("could not set up socketpair for '%s'"), path);
	}

	register_atexit(path);

	server_data = xcalloc(1, sizeof(*server_data));
	server_data->magic = MAGIC_SERVER_DATA;
	server_data->application_cb = application_cb;
	server_data->application_data = application_data;
	strbuf_init(&server_data->buf_path, 0);
	strbuf_addstr(&server_data->buf_path, path);

	if (nr_threads < 1)
		nr_threads = 1;

	pthread_mutex_init(&server_data->work_available_mutex, NULL);
	pthread_cond_init(&server_data->work_available_cond, NULL);

	server_data->queue_size = nr_threads * FIFO_SCALE;
	server_data->fifo_fds = xcalloc(server_data->queue_size,
					sizeof(*server_data->fifo_fds));

	server_data->accept_thread =
		xcalloc(1, sizeof(*server_data->accept_thread));
	server_data->accept_thread->magic = MAGIC_ACCEPT_THREAD_DATA;
	server_data->accept_thread->server_data = server_data;
	server_data->accept_thread->fd_listen = fd_listen;
	server_data->accept_thread->fd_send_shutdown = sv[0];
	server_data->accept_thread->fd_wait_shutdown = sv[1];

	if (pthread_create(&server_data->accept_thread->pthread_id, NULL,
			   accept_thread_proc, server_data->accept_thread))
		die_errno(_("could not start accept_thread '%s'"), path);

	for (k = 0; k < nr_threads; k++) {
		struct ipc_worker_thread_data *wtd;

		wtd = xcalloc(1, sizeof(*wtd));
		wtd->magic = MAGIC_WORKER_THREAD_DATA;
		wtd->server_data = server_data;

		if (pthread_create(&wtd->pthread_id, NULL, worker_thread_proc,
				   wtd)) {
			if (k == 0)
				die(_("could not start worker[0] for '%s'"),
				    path);
			/*
			 * Limp along with the thread pool that we have.
			 */
			break;
		}

		wtd->next_thread = server_data->worker_thread_list;
		server_data->worker_thread_list = wtd;
	}

	*returned_server_data = server_data;
	return 0;
}

/*
 * Gently tell the IPC server treads to shutdown.
 */
int ipc_server_stop_async(struct ipc_server_data *server_data)
{
	/* ASSERT NOT holding mutex */

	int fd;

	if (!server_data)
		return 0;

	pthread_mutex_lock(&server_data->work_available_mutex);

	server_data->shutdown_requested = 1;

	/*
	 * Write a byte to the shutdown socket pair to wake up the
	 * accept-thread.
	 */
	if (write(server_data->accept_thread->fd_send_shutdown, "Q", 1) < 0)
		error_errno("could not write to fd_send_shutdown");

	/*
	 * Drain the queue of existing connections.
	 */
	while ((fd = fifo_dequeue(server_data)) != -1)
		close(fd);

	/*
	 * Gently tell worker threads to stop processing new connections
	 * and exit.  (This does not abort in-process conversations.)
	 */
	pthread_cond_broadcast(&server_data->work_available_cond);

	pthread_mutex_unlock(&server_data->work_available_mutex);

	return 0;
}

/*
 * Wait for all IPC server threads to stop.
 */
int ipc_server_await(struct ipc_server_data *server_data)
{
	pthread_join(server_data->accept_thread->pthread_id, NULL);

	if (!server_data->shutdown_requested)
		BUG("ipc-server: accept-thread stopped for '%s'",
		    server_data->buf_path.buf);

	while (server_data->worker_thread_list) {
		struct ipc_worker_thread_data *wtd =
			server_data->worker_thread_list;

		pthread_join(wtd->pthread_id, NULL);

		server_data->worker_thread_list = wtd->next_thread;
		free(wtd);
	}

	server_data->is_stopped = 1;

	return 0;
}

void ipc_server_free(struct ipc_server_data *server_data)
{
	if (!server_data)
		return;

	if (!server_data->is_stopped)
		BUG("cannot free ipc-server while running for '%s'",
		    server_data->buf_path.buf);

	strbuf_release(&server_data->buf_path);

	if (server_data->accept_thread) {
		if (server_data->accept_thread->fd_listen != -1)
			close(server_data->accept_thread->fd_listen);
		if (server_data->accept_thread->fd_send_shutdown != -1)
			close(server_data->accept_thread->fd_send_shutdown);
		if (server_data->accept_thread->fd_wait_shutdown != -1)
			close(server_data->accept_thread->fd_wait_shutdown);
		free(server_data->accept_thread);
	}

	while (server_data->worker_thread_list) {
		struct ipc_worker_thread_data *wtd =
			server_data->worker_thread_list;

		server_data->worker_thread_list = wtd->next_thread;
		free(wtd);
	}

	pthread_cond_destroy(&server_data->work_available_cond);
	pthread_mutex_destroy(&server_data->work_available_mutex);

	free(server_data->fifo_fds);
	free(server_data);
}

int ipc_server_run(const char *path, int nr_threads,
		   ipc_server_application_cb *application_cb,
		   void *application_data)
{
	struct ipc_server_data *server_data = NULL;
	int ret;

	ret = ipc_server_run_async(&server_data, path, nr_threads,
				   application_cb, application_data);
	if (ret)
		return ret;

	ret = ipc_server_await(server_data);

	ipc_server_free(server_data);

	return ret;
}

#endif /* !NO_UNIX_SOCKETS */
