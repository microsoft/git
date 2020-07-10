#include "cache.h"
#include "fsmonitor.h"

static int normalize_path(FILE_NOTIFY_INFORMATION *info, struct strbuf *normalized_path)
{
	/* Convert to UTF-8 */
	int len;

	strbuf_reset(normalized_path);
	strbuf_grow(normalized_path, 32768);
	len = WideCharToMultiByte(CP_UTF8, 0, info->FileName,
				  info->FileNameLength / sizeof(WCHAR),
				  normalized_path->buf, strbuf_avail(normalized_path) - 1, NULL, NULL);

	if (len == 0 || len >= 32768 - 1)
		return error("could not convert '%.*S' to UTF-8",
			     (int)(info->FileNameLength / sizeof(WCHAR)),
			     info->FileName);

	strbuf_setlen(normalized_path, len);
	return strbuf_normalize_path(normalized_path);
}

// TODO Calling TerminateThread is very unsafe.
// TODO We should have a way to notify the thread to exit.

int fsmonitor_listen_stop(struct fsmonitor_daemon_state *state)
{
	if (!TerminateThread(state->watcher_thread.handle, 1))
		return -1;

	return 0;
}

// TODO This is a thread-proc, right?
//
// TODO Add trace2_thread_start() and _exit()
//
// TODO This should not call exit(), rather goto end and returning.
//
// TODO The `return state` statements assume that someone is going to join
// TODO in order to recover that info, but the caller probably already has
// TODO the state (because it needs the pthread_id to call join).  So this
// TODO is probably not needed.  That is, just return NULL.
//
// TODO We should open `dir` in OVERLAPPED mode and create an hEvent for
// TODO shutdown and have the main loop here call `WaitForMultipleObjects`
// TODO and either get data or a shutdown signal.  See what I did in simple-ipc--win32.c
// TODO in `queue_overlapped_connect()` and `wait_for_connection()` and the
// TODO body of `server_thread_proc()`.
// TODO
// TODO Then `fsmonitor_list_stop()` would just need to do what I did in
// TODO `ipc_server_stop_async()`.

struct fsmonitor_daemon_state *fsmonitor_listen(struct fsmonitor_daemon_state *state)
{
	HANDLE dir;
	char buffer[65536 * sizeof(wchar_t)], *p;
	DWORD desired_access = FILE_LIST_DIRECTORY;
	DWORD share_mode =
		FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE;
	DWORD count = 0;
	int i;

	dir = CreateFileW(L".", desired_access, share_mode, NULL, OPEN_EXISTING,
			  FILE_FLAG_BACKUP_SEMANTICS, NULL);
	pthread_mutex_lock(&state->initial_mutex);
	state->latest_update = getnanotime();
	state->initialized = 1;
	pthread_cond_signal(&state->initial_cond);
	pthread_mutex_unlock(&state->initial_mutex);

	for (;;) {
		struct fsmonitor_queue_item dummy, *queue = &dummy;
		struct strbuf path = STRBUF_INIT;
		uint64_t time = getnanotime();

		/* Ensure strictly increasing timestamps */
		pthread_mutex_lock(&state->queue_update_lock);
		if (time <= state->latest_update)
			time = state->latest_update + 1;
		pthread_mutex_unlock(&state->queue_update_lock);

		if (!ReadDirectoryChangesW(dir, buffer, sizeof(buffer), TRUE,
					   FILE_NOTIFY_CHANGE_FILE_NAME |
					   FILE_NOTIFY_CHANGE_DIR_NAME |
					   FILE_NOTIFY_CHANGE_ATTRIBUTES |
					   FILE_NOTIFY_CHANGE_SIZE |
					   FILE_NOTIFY_CHANGE_LAST_WRITE |
					   FILE_NOTIFY_CHANGE_CREATION,
					   &count, NULL, NULL)) {
			error("Reading Directory Change failed");
			continue;
		}

		p = buffer;
		for (;;) {
			FILE_NOTIFY_INFORMATION *info = (void *)p;
			int special;

			normalize_path(info, &path);

			special = fsmonitor_special_path(state, path.buf,
							 path.len,
							 info->Action ==
							 FILE_ACTION_REMOVED);

			if (!special &&
			    fsmonitor_queue_path(state, &queue, path.buf,
						 path.len, time) < 0) {
				CloseHandle(dir);
				state->error_code = -1;
				error("could not queue '%s'; exiting",
				      path.buf);
				return state;
			} else if (special == FSMONITOR_DAEMON_QUIT) {
				CloseHandle(dir);
				/* force-quit */
				exit(0);
			} else if (special < 0)
				return state;

			if (!info->NextEntryOffset)
				break;
			p += info->NextEntryOffset;
		}

		/* Only update the queue if it changed */
		if (queue != &dummy) {
			pthread_mutex_lock(&state->queue_update_lock);
			if (state->first)
				state->first->previous = dummy.previous;
			dummy.previous->next = state->first;
			state->first = queue;
			state->latest_update = time;
			pthread_mutex_unlock(&state->queue_update_lock);
		}

		for (i = 0; i < state->cookie_list.nr; i++)
			fsmonitor_cookie_seen_trigger(state, state->cookie_list.items[i].string);

		string_list_clear(&state->cookie_list, 0);
		strbuf_release(&path);
	}

	return state;
}
