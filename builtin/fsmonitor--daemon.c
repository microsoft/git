/*
 * built-in fsmonitor daemon
 *
 * Monitor filesystem changes to update the Git index intelligently.
 *
 * Copyright (c) 2019 Johannes Schindelin
 */

#include "builtin.h"
#include "parse-options.h"
#include "fsmonitor.h"
#include "simple-ipc.h"
#include "khash.h"

static const char * const builtin_fsmonitor__daemon_usage[] = {
	N_("git fsmonitor--daemon [--query] <version> <timestamp>"),
	N_("git fsmonitor--daemon <command-mode> [<options>...]"),
	NULL
};

#ifndef HAVE_FSMONITOR_DAEMON_BACKEND
#define FSMONITOR_DAEMON_IS_SUPPORTED 0
#define FSMONITOR_VERSION 0l

static int fsmonitor_query_daemon(const char *unused_since,
				  struct strbuf *unused_answer)
{
	die(_("no native fsmonitor daemon available"));
}

static int fsmonitor_run_daemon(int unused_background)
{
	die(_("no native fsmonitor daemon available"));
}

static int fsmonitor_daemon_is_running(void)
{
	warning(_("no native fsmonitor daemon available"));
	return 0;
}

static int fsmonitor_stop_daemon(void)
{
	warning(_("no native fsmonitor daemon available"));
	return 0;
}
#else
#define FSMONITOR_DAEMON_IS_SUPPORTED 1

// TODO Should there be a timeout on how long we wait for the
// TODO cookie file to appear in the notification stream?
// TODO This wait will block the `handle_client()` thread (which
// TODO blockes the response to the client) and which is running
// TODO in one of the IPC thread pool worker threads.  Which
// TODO could cause the the daemon to become unresponsive (if
// TODO several worker threads get stuck).

static void fsmonitor_wait_for_cookie(struct fsmonitor_daemon_state *state)
{
	int fd;
	struct fsmonitor_cookie_item cookie;
	const char *cookie_path;
	struct strbuf cookie_filename = STRBUF_INIT;

	strbuf_addstr(&cookie_filename, FSMONITOR_COOKIE_PREFIX);
	strbuf_addf(&cookie_filename, "%i-%i", getpid(), state->cookie_seq++);
	cookie.name = strbuf_detach(&cookie_filename, NULL);
	cookie.seen = 0;
	hashmap_entry_init(&cookie.entry, strhash(cookie.name));
	pthread_mutex_init(&cookie.seen_lock, NULL);
	pthread_cond_init(&cookie.seen_cond, NULL);

	// TODO Putting the address of a stack variable into a global
	// TODO hashmap feels dodgy.  Granted, the `handle_client()`
	// TODO stack frame is in a thread that will block on this
	// TODO returning, but do all coce paths guarantee that it is
	// TODO removed from the hashmap before this stack frame returns?

	pthread_mutex_lock(&state->cookies_lock);
	hashmap_add(&state->cookies, &cookie.entry);
	pthread_mutex_unlock(&state->cookies_lock);
	cookie_path = git_pathdup("%s", cookie.name);
	fd = open(cookie_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd >= 0) {
		close(fd);
		pthread_mutex_lock(&cookie.seen_lock);
		while (!cookie.seen)
			pthread_cond_wait(&cookie.seen_cond, &cookie.seen_lock);
		cookie.seen = 0;
		pthread_mutex_unlock(&cookie.seen_lock);
		unlink_or_warn(cookie_path);

		// TODO Here we have been signalled that the file
		// TODO has appeared.  Shouldn't we remove the cookie
		// TODO from the hashmap and destroy the _mutex and _cond
		// TODO vars.  (It looks like _trigger does remove it, so
		// TOOD maybe just destroy the vars.)
		//
		// TODO The unlink() will cause a second notification.
		// TODO Is that significant?  (It looks like the was_deleted)
		// TODO bit guards that.)

	} else {
		pthread_mutex_lock(&state->cookies_lock);
		hashmap_remove(&state->cookies, &cookie.entry, NULL);
		pthread_mutex_unlock(&state->cookies_lock);

		// TODO What happens if we cannot create the cookie file?
		// TODO We don't block the current thread.  The caller
		// TODO will continue as is and maybe report an incomplete
		// TODO snapshot ??
		//
		// TODO If we cannot create the file, we should remove
		// TODO this cookie from the hashmap, right?
		//
		// TODO And destroy cookie.seen_lock and cookie.seen_cond.
	}
}

void fsmonitor_cookie_seen_trigger(struct fsmonitor_daemon_state *state,
				   const char *cookie_name)
{
	struct fsmonitor_cookie_item key;
	struct fsmonitor_cookie_item *cookie;

	hashmap_entry_init(&key.entry, strhash(cookie_name));
	key.name = cookie_name;
	cookie = hashmap_get_entry(&state->cookies, &key, entry, NULL);

	if (cookie) {
		pthread_mutex_lock(&cookie->seen_lock);
		cookie->seen = 1;
		pthread_cond_signal(&cookie->seen_cond);
		pthread_mutex_unlock(&cookie->seen_lock);

		// TODO Here we are removing the cookie from the hashmap.
		// TODO This requires reaching into the cookie for the key,
		// TODO right?  The cookie was added using a stack variable
		// TODO in the `handle_client()` thread -- the thread we just
		// TODO woke up.  So it might be possible for that thread to
		// TODO have returned and possibly have trashed the content
		// TODO of this cookie.  This could make this hashmap operation
		// TODO unsafe, right?

		pthread_mutex_lock(&state->cookies_lock);
		hashmap_remove(&state->cookies, &cookie->entry, NULL);
		pthread_mutex_unlock(&state->cookies_lock);
	}
}

KHASH_INIT(str, const char *, int, 0, kh_str_hash_func, kh_str_hash_equal);

static ipc_server_application_cb handle_client;

static int handle_client(void *data, const char *command,
			 ipc_server_reply_cb *reply,
			 struct ipc_server_reply_data *reply_data)
{
	struct fsmonitor_daemon_state *state = data;
	unsigned long version;
	uintmax_t since;
	char *p;
	struct fsmonitor_queue_item *queue;
	struct strbuf token = STRBUF_INIT;
	intmax_t count = 0, duplicates = 0;
	kh_str_t *shown;
	int hash_ret;

	trace2_data_string("fsmonitor", the_repository, "command", command);

	if (!strcmp(command, "quit")) {
		if (fsmonitor_listen_stop(state))
			error("Could not terminate watcher thread");
		/* TODO: figure out whether we can do better */
		sleep_millisec(50);
		return SIMPLE_IPC_QUIT;
	}

	trace2_region_enter("fsmonitor", "serve", the_repository);

	version = strtoul(command, &p, 10);
	if (version != FSMONITOR_VERSION) {
		error(_("fsmonitor: unhandled version (%lu, command: %s)"),
		      version, command);
error:
		pthread_mutex_lock(&state->queue_update_lock);
		strbuf_addf(&token, "%"PRIu64"", state->latest_update);
		pthread_mutex_unlock(&state->queue_update_lock);
		reply(reply_data, token.buf, token.len + 1);
		reply(reply_data, "/", 2);
		strbuf_release(&token);
		trace2_region_leave("fsmonitor", "serve", the_repository);
		return -1;
	}
	while (isspace(*p))
		p++;
	since = strtoumax(p, &p, 10);

	/*
	 * write out cookie file so the queue gets filled with all
	 * the file system events that happen before the file gets written
	 */
	fsmonitor_wait_for_cookie(state);

	pthread_mutex_lock(&state->queue_update_lock);
	if (since < state->latest_update || *p) {
		pthread_mutex_unlock(&state->queue_update_lock);
		error(_("fsmonitor: %s (%" PRIuMAX", command: %s, rest %s)"),
		      *p ? "extra stuff" : "incorrect/early timestamp",
		      since, command, p);
		goto error;
	}

	if (!state->latest_update)
		BUG("latest_update was not updated");

	queue = state->first;
	strbuf_addf(&token, "%"PRIu64"", state->latest_update);
	pthread_mutex_unlock(&state->queue_update_lock);

	reply(reply_data, token.buf, token.len + 1);
	shown = kh_init_str();
	while (queue && queue->time >= since) {
		if (kh_get_str(shown, queue->path->path) != kh_end(shown))
			duplicates++;
		else {
			kh_put_str(shown, queue->path->path, &hash_ret);

			// TODO This loop is writing 1 pathname at a time.
			// TODO This causes a pkt-line write per file.
			// TODO This will cause a context switch as the client
			// TODO will try to do a pkt-line read.
			// TODO We should consider sending a batch in a
			// TODO large buffer.
			//
			// TODO This add a NUL to the per-line payload.
			// TODO If the client re-assembles a multi-reply
			// TODO response will it get the null bytes inside
			// TODO the buffer?  The API is described as a string,
			// TODO so I think there is an opportunity for confusion
			// TODO and getting individual lines concatenated.

			/* write the path, followed by a NUL */
			if (reply(reply_data,
				  queue->path->path, queue->path->len + 1) < 0)
				break;
			trace2_data_string("fsmonitor", the_repository,
					   "serve.path", queue->path->path);
			count++;
		}
		queue = queue->next;
	}

	kh_release_str(shown);
	strbuf_release(&token);
	trace2_data_intmax("fsmonitor", the_repository, "serve.count", count);
	trace2_data_intmax("fsmonitor", the_repository, "serve.skipped-duplicates", duplicates);
	trace2_region_leave("fsmonitor", "serve", the_repository);

	return 0;
}

static int paths_cmp(const void *data, const struct hashmap_entry *he1,
		     const struct hashmap_entry *he2, const void *keydata)
{
	const struct fsmonitor_path *a =
		container_of(he1, const struct fsmonitor_path, entry);
	const struct fsmonitor_path *b =
		container_of(he2, const struct fsmonitor_path, entry);

	return strcmp(a->path, keydata ? keydata : b->path);
}

int fsmonitor_special_path(struct fsmonitor_daemon_state *state,
			   const char *path, size_t len, int was_deleted)
{
	if (len < 4 || fspathncmp(path, ".git", 4) || (path[4] && path[4] != '/'))
		return 0;

	if (was_deleted && (len == 4 || len == 5))
		return FSMONITOR_DAEMON_QUIT;

	if (!was_deleted && len > 4 &&
	    starts_with(path + 5, FSMONITOR_COOKIE_PREFIX))
		string_list_append(&state->cookie_list, path + 5);

	return 1;
}

static int cookies_cmp(const void *data, const struct hashmap_entry *he1,
		     const struct hashmap_entry *he2, const void *keydata)
{
	const struct fsmonitor_cookie_item *a =
		container_of(he1, const struct fsmonitor_cookie_item, entry);
	const struct fsmonitor_cookie_item *b =
		container_of(he2, const struct fsmonitor_cookie_item, entry);

	return strcmp(a->name, keydata ? keydata : b->name);
}

int fsmonitor_queue_path(struct fsmonitor_daemon_state *state,
			 struct fsmonitor_queue_item **queue,
			 const char *path, size_t len, uint64_t time)
{
	struct fsmonitor_path lookup, *e;
	struct fsmonitor_queue_item *item;

	hashmap_entry_init(&lookup.entry, len);
	lookup.path = path;
	lookup.len = len;
	e = hashmap_get_entry(&state->paths, &lookup, entry, NULL);

	if (!e) {
		FLEXPTR_ALLOC_MEM(e, path, path, len);
		e->len = len;
		hashmap_put(&state->paths, &e->entry);
	}

	trace2_data_string("fsmonitor", the_repository, "path", e->path);

	item = xmalloc(sizeof(*item));
	item->path = e;
	item->time = time;
	item->previous = NULL;
	item->next = *queue;
	(*queue)->previous = item;
	*queue = item;

	return 0;
}

static int fsmonitor_run_daemon(int background)
{
	struct fsmonitor_daemon_state state = {
		.cookie_list = STRING_LIST_INIT_DUP
	};

	if (background && daemonize())
		BUG(_("daemonize() not supported on this platform"));

	hashmap_init(&state.paths, paths_cmp, NULL, 0);
	hashmap_init(&state.cookies, cookies_cmp, NULL, 0);
	pthread_mutex_init(&state.queue_update_lock, NULL);
	pthread_mutex_init(&state.cookies_lock, NULL);
	pthread_mutex_init(&state.initial_mutex, NULL);
	pthread_cond_init(&state.initial_cond, NULL);

	pthread_mutex_lock(&state.initial_mutex);
	if (pthread_create(&state.watcher_thread, NULL,
			   (void *(*)(void *)) fsmonitor_listen, &state) < 0)
		return error(_("could not start fsmonitor listener thread"));

	/* wait for the thread to signal that it is ready */
	while (!state.initialized)
		pthread_cond_wait(&state.initial_cond, &state.initial_mutex);
	pthread_mutex_unlock(&state.initial_mutex);

	// TODO I harded coded 8 threads for the IPC layer.  Should make this
	// TODO a config setting or something.

	return ipc_server_run(git_path_fsmonitor(), 8, handle_client, &state);

	// TODO We should join on the listener thread.
}
#endif

int cmd_fsmonitor__daemon(int argc, const char **argv, const char *prefix)
{
	enum daemon_mode {
		QUERY = 0, RUN, START, STOP, IS_RUNNING, IS_SUPPORTED
	} mode = QUERY;
	struct option options[] = {
		OPT_CMDMODE(0, "query", &mode, N_("query the daemon"), QUERY),
		OPT_CMDMODE(0, "run", &mode, N_("run the daemon"), RUN),
		OPT_CMDMODE(0, "start", &mode, N_("run in the background"),
			    START),
		OPT_CMDMODE(0, "stop", &mode, N_("stop the running daemon"),
			    STOP),
		OPT_CMDMODE('t', "is-running", &mode,
			    N_("test whether the daemon is running"),
			    IS_RUNNING),
		OPT_CMDMODE(0, "is-supported", &mode,
			    N_("determine internal fsmonitor on this platform"),
			    IS_SUPPORTED),
		OPT_END()
	};

	if (argc == 2 && !strcmp(argv[1], "-h"))
		usage_with_options(builtin_fsmonitor__daemon_usage, options);

	argc = parse_options(argc, argv, prefix, options,
			     builtin_fsmonitor__daemon_usage, 0);

	if (mode == QUERY) {
		struct strbuf answer = STRBUF_INIT;
		int ret;
		unsigned long version;

		if (argc != 2)
			usage_with_options(builtin_fsmonitor__daemon_usage,
					   options);

		version = strtoul(argv[0], NULL, 10);
		if (version != FSMONITOR_VERSION)
			die(_("unhandled fsmonitor version %ld (!= %ld)"),
			      version, FSMONITOR_VERSION);

		ret = fsmonitor_query_daemon(argv[1], &answer);
		if (ret < 0)
			die(_("could not query fsmonitor daemon"));
		write_in_full(1, answer.buf, answer.len);
		strbuf_release(&answer);

		return 0;
	}

	if (argc != 0)
		usage_with_options(builtin_fsmonitor__daemon_usage, options);

	if (mode == IS_SUPPORTED)
		return !FSMONITOR_DAEMON_IS_SUPPORTED;

	if (mode == IS_RUNNING)
		return !fsmonitor_daemon_is_running();

	if (mode == STOP) {
		if (fsmonitor_stop_daemon() < 0)
			die("could not stop daemon");
		while (fsmonitor_daemon_is_running())
			sleep_millisec(50);
		return 0;
	}

	if (fsmonitor_daemon_is_running())
		die("fsmonitor daemon is already running.");

#ifdef GIT_WINDOWS_NATIVE
	/* Windows cannot daemonize(); emulate it */
	if (mode == START)
		return !!fsmonitor_spawn_daemon();
#endif

	return !!fsmonitor_run_daemon(mode == START);
}

// TODO BIG PICTURE QUESTION:
// TODO Is there an inherent race condition in this whole thing?
// TODO The client asks for all changes since a given timestamp.
// TODO The server creates a cookie file and blocks the response
// TODO until it appears.
// TODO  [1] The cookie is created at a random time (WRT the client)
// TODO      (and considering the race for the daemon to accept()
// TODO      the client connection).
// TODO  [2] The fs notify code handles events in batches
// TODO  [3] The response is everything from the requested timestamp
// TODO      thru the end of the batch (another bit of randomness).
// TODO
// TODO I'm wondering if the client should create the cookie file
// TODO and then ask for everything from a given timestamp UPTO AND
// TODO the cookie file event.
// TODO  [1] This would remove some of the randomness WRT the
// TODO      client and the last event reported.
// TODO  [2] The client would be responsible for creating and deleting
// TODO      the cookie file -- so the daemon would not need write
// TODO      access to the repo.
// TODO  [3] The cookie file creation event could be arriving WHILE
// TODO      connection is established.
// TODO  [4] The client could decide the timeout (and just hang up).
//
