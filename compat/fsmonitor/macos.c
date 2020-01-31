/*
 * Let Apple's headers declare `isalnum()` first, before
 * Git's headers override it via a constant
 */
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

#include "cache.h"
#include "fsmonitor.h"

static struct strbuf watch_dir = STRBUF_INIT;
static FSEventStreamRef stream;

static void fsevent_callback(ConstFSEventStreamRef streamRef,
			     void *ctx,
			     size_t num_of_events,
			     void * event_paths,
			     const FSEventStreamEventFlags event_flags[],
			     const FSEventStreamEventId event_ids[])
{
	int i;
	struct stat st;
	char **paths = (char **)event_paths;
	struct fsmonitor_queue_item dummy, *queue = &dummy;
	uint64_t time = getnanotime();
	struct fsmonitor_daemon_state *state = ctx;

	/* Ensure strictly increasing timestamps */
	pthread_mutex_lock(&state->queue_update_lock);
	if (time <= state->latest_update)
		time = state->latest_update + 1;
	pthread_mutex_unlock(&state->queue_update_lock);

	for (i = 0; i < num_of_events; i++) {
		int special;
		const char *path = paths[i] + watch_dir.len;
		size_t len = strlen(path);

		if (*path == '/') {
			path++;
			len--;
		}

		special = fsmonitor_special_path(state, path, len,
						 (event_flags[i] & (kFSEventStreamEventFlagRootChanged | kFSEventStreamEventFlagItemRemoved)) &&
						 lstat(paths[i], &st));

		if ((event_flags[i] & kFSEventStreamEventFlagKernelDropped) ||
		    (event_flags[i] & kFSEventStreamEventFlagUserDropped)) {
			trace2_data_string("fsmonitor", the_repository, "message", "Dropped event");
			fsmonitor_queue_path(state, &queue, "/", 1, time);
		}

		if (!special && fsmonitor_queue_path(state, &queue,
						     path, len, time) < 0) {
			state->error_code = -1;
			error("could not queue '%s'; exiting",
			      path);
			fsmonitor_listen_stop(state);
			return;
		} else if (special == FSMONITOR_DAEMON_QUIT) {
			trace2_data_string("fsmonitor", the_repository, "message", ".git directory being removed so quitting.");
			exit(0);

		} else if (special < 0) {
			fsmonitor_listen_stop(state);
			return;
		}
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
}

struct fsmonitor_daemon_state *fsmonitor_listen(struct fsmonitor_daemon_state *state)
{
	FSEventStreamCreateFlags flags = kFSEventStreamCreateFlagNoDefer |
		kFSEventStreamCreateFlagWatchRoot |
		kFSEventStreamCreateFlagFileEvents;
	CFStringRef watch_path;
	CFArrayRef paths_to_watch;
	FSEventStreamContext ctx = {
		0,
		state,
		NULL,
		NULL,
		NULL
	};

	trace2_region_enter("fsmonitor", "fsevents", the_repository);
	strbuf_addstr(&watch_dir, get_git_work_tree());
	trace2_printf("Start watching: '%s' for fsevents", watch_dir.buf);

	watch_path = CFStringCreateWithCString(NULL, watch_dir.buf, kCFStringEncodingUTF8);
	paths_to_watch = CFArrayCreate(NULL, (const void **)&watch_path, 1, NULL);
	stream = FSEventStreamCreate(NULL, fsevent_callback, &ctx, paths_to_watch,
				     kFSEventStreamEventIdSinceNow, 0.1, flags);
	if (stream == NULL)
		die("Unable to create FSEventStream.");

	FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	if (!FSEventStreamStart(stream))
		die("Failed to start the FSEventStream");

	pthread_mutex_lock(&state->initial_mutex);
	state->latest_update = getnanotime();
	state->initialized = 1;
	pthread_cond_signal(&state->initial_cond);
	pthread_mutex_unlock(&state->initial_mutex);

	CFRunLoopRun();

	trace2_region_leave("fsmonitor", "fsevents", the_repository);
	return state;
}

int fsmonitor_listen_stop(struct fsmonitor_daemon_state *state)
{
	CFRunLoopStop(CFRunLoopGetCurrent());
	FSEventStreamStop(stream);
	FSEventStreamInvalidate(stream);
	FSEventStreamRelease(stream);
	return 0;
}
