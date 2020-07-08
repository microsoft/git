/*
 * test-simple-ipc.c: verify that the Inter-Process Communication works.
 */

#include "test-tool.h"
#include "cache.h"
#include "strbuf.h"
#include "simple-ipc.h"
#include "parse-options.h"
#include "thread-utils.h"

#ifndef SUPPORTS_SIMPLE_IPC
int cmd__simple_ipc(int argc, const char **argv)
{
	die("simple IPC not available on this platform");
}
#else

/*
 * The test daemon defines an "application callback" that supports a
 * series of commands (see `test_app_cb()`).
 *
 * Unknown commands are caught here and we send an error message back
 * to the client process.
 */
static int app__unhandled_command(const char *command,
				  ipc_server_reply_cb *reply_cb,
				  struct ipc_server_reply_data *reply_data)
{
	struct strbuf buf = STRBUF_INIT;
	int ret;

	strbuf_addf(&buf, "unhandled command: %s", command);
	ret = reply_cb(reply_data, buf.buf, buf.len);
	strbuf_release(&buf);

	return ret;
}

/*
 * Reply with a single very large buffer.  This is to ensure that
 * long response are properly handled -- whether the chunking occurs
 * in the kernel or in the (probably pkt-line) layer.
 */
#define BIG_ROWS (10000)
static int app__big_command(ipc_server_reply_cb *reply_cb,
			    struct ipc_server_reply_data *reply_data)
{
	struct strbuf buf = STRBUF_INIT;
	int row;
	int ret;

	for (row = 0; row < BIG_ROWS; row++)
		strbuf_addf(&buf, "big: %.75d\n", row);

	ret = reply_cb(reply_data, buf.buf, buf.len);
	strbuf_release(&buf);

	return ret;
}

/*
 * Reply with a series of lines.  This is to ensure that we can incrementally
 * compute the response and chunk it to the client.
 */
#define CHUNK_ROWS (10000)
static int app__chunk_command(ipc_server_reply_cb *reply_cb,
			      struct ipc_server_reply_data *reply_data)
{
	struct strbuf buf = STRBUF_INIT;
	int row;
	int ret;

	for (row = 0; row < CHUNK_ROWS; row++) {
		strbuf_setlen(&buf, 0);
		strbuf_addf(&buf, "big: %.75d\n", row);
		ret = reply_cb(reply_data, buf.buf, buf.len);
	}

	strbuf_release(&buf);

	return ret;
}

/*
 * Slowly reply with a series of lines.  This is to model an expensive to
 * compute chunked response (which might happen if this callback is running
 * in a thread and is fighting for a lock with other threads).
 */
#define SLOW_ROWS     (1000)
#define SLOW_DELAY_MS (10)
static int app__slow_command(ipc_server_reply_cb *reply_cb,
			     struct ipc_server_reply_data *reply_data)
{
	struct strbuf buf = STRBUF_INIT;
	int row;
	int ret;

	for (row = 0; row < SLOW_ROWS; row++) {
		strbuf_setlen(&buf, 0);
		strbuf_addf(&buf, "big: %.75d\n", row);
		ret = reply_cb(reply_data, buf.buf, buf.len);
		sleep_millisec(SLOW_DELAY_MS);
	}

	strbuf_release(&buf);

	return ret;
}

/*
 * The client sent a command followed by a (possibly very) large buffer.
 */
static int app__sendbytes_command(const char *received,
				  ipc_server_reply_cb *reply_cb,
				  struct ipc_server_reply_data *reply_data)
{
	struct strbuf buf_resp = STRBUF_INIT;
	const char *p = "?";
	int len_ballast = 0;
	int k;
	int errs = 0;
	int ret;

	if (skip_prefix(received, "sendbytes ", &p))
		len_ballast = strlen(p);

	/*
	 * Verify that the ballast is n copies of a single letter.
	 * And that the multi-threaded IO layer didn't cross the streams.
	 */
	for (k = 1; k < len_ballast; k++)
		if (p[k] != p[0])
			errs++;

	if (errs)
		strbuf_addf(&buf_resp, "errs:%d\n", errs);
	else
		strbuf_addf(&buf_resp, "rcvd:%c%08d\n", p[0], len_ballast);

	ret = reply_cb(reply_data, buf_resp.buf, buf_resp.len);

	strbuf_release(&buf_resp);

	return ret;
}

/*
 * An arbitrary fixed address to verify that the application instance
 * data is handled properly.
 */
static int my_app_data = 42;

static ipc_server_application_cb test_app_cb;

/*
 * This is "application callback" that sits on top of the "ipc-server".
 * It completely defines the set of command verbs supported by this
 * application.
 */
static int test_app_cb(void *application_data,
		       const char *command,
		       ipc_server_reply_cb *reply_cb,
		       struct ipc_server_reply_data *reply_data)
{
	/*
	 * Verify that we received the application-data that we passed
	 * when we started the ipc-server.  (We have several layers of
	 * callbacks calling callbacks and it's easy to get things mixed
	 * up (especially when some are "void*").)
	 */
	if (application_data != (void*)&my_app_data)
		BUG("application_cb: application_data pointer wrong");

	if (!strcmp(command, "quit")) {
		/*
		 * Tell ipc-server to hangup with an empty reply.
		 */
		return SIMPLE_IPC_QUIT;
	}

	if (!strcmp(command, "ping")) {
		const char *answer = "pong";
		return reply_cb(reply_data, answer, strlen(answer));
	}

	if (!strcmp(command, "big"))
		return app__big_command(reply_cb, reply_data);

	if (!strcmp(command, "chunk"))
		return app__chunk_command(reply_cb, reply_data);

	if (!strcmp(command, "slow"))
		return app__slow_command(reply_cb, reply_data);

	if (starts_with(command, "sendbytes "))
		return app__sendbytes_command(command, reply_cb, reply_data);

	return app__unhandled_command(command, reply_cb, reply_data);
}

/*
 * This process will run as a simple-ipc server and listen for IPC commands
 * from client processes.
 */
static int daemon__run_server(const char *path, int argc, const char **argv)
{
	int nr_threads = 5;

	const char * const daemon_usage[] = {
		N_("test-helper simple-ipc daemon [<options>"),
		NULL
	};
	struct option daemon_options[] = {
		OPT_INTEGER(0, "threads", &nr_threads,
			    N_("number of threads in server thread pool")),
		OPT_END()
	};

	argc = parse_options(argc, argv, NULL, daemon_options, daemon_usage, 0);

	if (nr_threads < 1)
		nr_threads = 1;

	/*
	 * Synchronously run the ipc-server.  We don't need any application
	 * instance data, so pass an arbitrary pointer (that we'll later
	 * verify made the round trip).
	 */
	return ipc_server_run(path, nr_threads, test_app_cb,
			      (void*)&my_app_data);
}

/*
 * This process will run a quick probe to see if a simple-ipc server
 * is active on this path.
 *
 * Returns 0 if the server is alive.
 */
static int client__probe_server(const char *path)
{
	enum IPC_ACTIVE_STATE s;
	int i;

	/*
	 * The test script will start the daemon in the background,
	 * meaning that it might not be fully set up by the time we are
	 * verifying that the IPC is active. So let's keep trying for
	 * up to 2.5 seconds (but only if we were able to normalize
	 * the path).
	 */
	for (i = 0; i < 50; i++) {
		s = ipc_is_active(path);
		switch (s) {
		case IPC_STATE__ACTIVE:
			return 0;

		case IPC_STATE__INVALID_PATH:
			return error("invalid pipe/socket name '%s'",
				     path);

		case IPC_STATE__NOT_ACTIVE:
		default:
			sleep_millisec(50);
			break;
		}
	}

	return error("no server listening at '%s'?", path);
}

/*
 * Send an IPC command to an already-running server daemon and print the
 * response.
 *
 * argv[2] contains a simple (1 word) command verb that `test_app_cb()`
 * (in the daemon process) will understand.
 */
static int client__send_ipc(int argc, const char **argv, const char *path)
{
	const char *command = argc > 2 ? argv[2] : "(no command)";
	struct strbuf buf = STRBUF_INIT;
	int is_quit = !strcmp("quit", command);

	if (!ipc_client_send_command(path, command, &buf)) {
		printf("%s\n", buf.buf);
		fflush(stdout);
		strbuf_release(&buf);

		return 0;
	}

	if (is_quit && (errno == ENOENT || errno == ECONNRESET))
		return 0;

	return error("failed to send '%s' to '%s'", command, path);
}

/*
 * Send an IPC command followed by ballast to confirm that a large
 * message can be sent and that the kernel or pkt-line layers will
 * properly chunk it and that the daemon receives the entire message.
 */
static int do_sendbytes(int bytecount, char byte, const char *path)
{
	struct strbuf buf_send = STRBUF_INIT;
	struct strbuf buf_resp = STRBUF_INIT;

	strbuf_addstr(&buf_send, "sendbytes ");
	strbuf_addchars(&buf_send, byte, bytecount);

	if (!ipc_client_send_command(path, buf_send.buf, &buf_resp)) {
		strbuf_rtrim(&buf_resp);
		printf("sent:%c%08d %s\n", byte, bytecount, buf_resp.buf);
		fflush(stdout);
		strbuf_release(&buf_send);
		strbuf_release(&buf_resp);

		return 0;
	}

	return error("client failed to sendbytes(%d, '%c') to '%s'",
		     bytecount, byte, path);
}

/*
 * Send an IPC command with ballast to an already-running server daemon.
 */
static int client__sendbytes(int argc, const char **argv, const char *path)
{
	int bytecount = 1024;
	char *string = "x";
	const char * const sendbytes_usage[] = {
		N_("test-helper simple-ipc sendbytes [<options>]"),
		NULL
	};
	struct option sendbytes_options[] = {
		OPT_INTEGER(0, "bytecount", &bytecount, N_("number of bytes")),
		OPT_STRING(0, "byte", &string, N_("byte"), N_("ballast")),
		OPT_END()
	};

	argc = parse_options(argc, argv, NULL, sendbytes_options, sendbytes_usage, 0);

	return do_sendbytes(bytecount, string[0], path);
}

struct multiple_thread_data {
	pthread_t pthread_id;
	struct multiple_thread_data *next;
	const char *path;
	int bytecount;
	int batchsize;
	int sum_errors;
	int sum_good;
	char letter;
};

static void *multiple_thread_proc(void *_multiple_thread_data)
{
	struct multiple_thread_data *d = _multiple_thread_data;
	int k;

	trace2_thread_start("multiple");

	for (k = 0; k < d->batchsize; k++) {
		if (do_sendbytes(d->bytecount + k, d->letter, d->path))
			d->sum_errors++;
		else
			d->sum_good++;
	}

	trace2_thread_exit();
	return NULL;
}

/*
 * Start a client-side thread pool.  Each thread sends a series of
 * IPC requests.  Each request is on a new connection to the server.
 */
static int client__multiple(int argc, const char **argv, const char *path)
{
	struct multiple_thread_data *list = NULL;
	int k;
	int nr_threads = 5;
	int bytecount = 1;
	int batchsize = 10;
	int sum_join_errors = 0;
	int sum_thread_errors = 0;
	int sum_good = 0;

	const char * const multiple_usage[] = {
		N_("test-helper simple-ipc multiple [<options>]"),
		NULL
	};
	struct option multiple_options[] = {
		OPT_INTEGER(0, "bytecount", &bytecount, N_("number of bytes")),
		OPT_INTEGER(0, "threads", &nr_threads, N_("number of threads")),
		OPT_INTEGER(0, "batchsize", &batchsize, N_("number of requests per thread")),
		OPT_END()
	};

	argc = parse_options(argc, argv, NULL, multiple_options, multiple_usage, 0);

	if (bytecount < 1)
		bytecount = 1;
	if (nr_threads < 1)
		nr_threads = 1;
	if (batchsize < 1)
		batchsize = 1;

	for (k = 0; k < nr_threads; k++) {
		struct multiple_thread_data *d = xcalloc(1, sizeof(*d));
		d->next = list;
		d->path = path;
		d->bytecount = bytecount + batchsize*(k/26);
		d->batchsize = batchsize;
		d->sum_errors = 0;
		d->sum_good = 0;
		d->letter = 'A' + (k % 26);

		if (pthread_create(&d->pthread_id, NULL, multiple_thread_proc, d)) {
			warning("failed to create thread[%d] skipping remainder", k);
			free(d);
			break;
		}

		list = d;
	}

	while (list) {
		struct multiple_thread_data *d = list;

		if (pthread_join(d->pthread_id, NULL))
			sum_join_errors++;

		sum_thread_errors += d->sum_errors;
		sum_good += d->sum_good;

		list = d->next;
		free(d);
	}

	printf("client (good %d) (join %d), (errors %d)\n",
	       sum_good, sum_join_errors, sum_thread_errors);

	return (sum_join_errors + sum_thread_errors) ? 1 : 0;
}

int cmd__simple_ipc(int argc, const char **argv)
{
	const char *path = "ipc-test";

	if (argc == 2 && !strcmp(argv[1], "SUPPORTS_SIMPLE_IPC"))
		return 0;

	/* Use '!!' on all dispatch functions to map from `error()` style
	 * (returns -1) style to `test_must_fail` style (expects 1) and
	 * get less confusing shell error messages.
	 */

	if (argc == 2 && !strcmp(argv[1], "is-active"))
		return !!client__probe_server(path);

	if (argc >= 2 && !strcmp(argv[1], "daemon"))
		return !!daemon__run_server(path, argc, argv);

	/*
	 * Client commands follow.  Ensure a server is running before
	 * going any further.
	 */
	if (client__probe_server(path))
		return 1;

	if ((argc == 2 || argc == 3) && !strcmp(argv[1], "send"))
		return !!client__send_ipc(argc, argv, path);

	if (argc >= 2 && !strcmp(argv[1], "sendbytes"))
		return !!client__sendbytes(argc, argv, path);

	if (argc >= 2 && !strcmp(argv[1], "multiple"))
		return !!client__multiple(argc, argv, path);

	die("Unhandled argv[1]: '%s'", argv[1]);
}
#endif
