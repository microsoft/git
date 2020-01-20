#ifndef FSMONITOR_H
#define FSMONITOR_H

#include "cache.h"
#include "dir.h"
#include "run-command.h"

extern struct trace_key trace_fsmonitor;

/*
 * Read the fsmonitor index extension and (if configured) restore the
 * CE_FSMONITOR_VALID state.
 */
int read_fsmonitor_extension(struct index_state *istate, const void *data, unsigned long sz);

/*
 * Fill the fsmonitor_dirty ewah bits with their state from the index,
 * before it is split during writing.
 */
void fill_fsmonitor_bitmap(struct index_state *istate);

/*
 * Write the CE_FSMONITOR_VALID state into the fsmonitor index
 * extension.  Reads from the fsmonitor_dirty ewah in the index.
 */
void write_fsmonitor_extension(struct strbuf *sb, struct index_state *istate);

/*
 * Add/remove the fsmonitor index extension
 */
void add_fsmonitor(struct index_state *istate);
void remove_fsmonitor(struct index_state *istate);

/*
 * Add/remove the fsmonitor index extension as necessary based on the current
 * core.fsmonitor setting.
 */
void tweak_fsmonitor(struct index_state *istate);

/*
 * Run the configured fsmonitor integration script and clear the
 * CE_FSMONITOR_VALID bit for any files returned as dirty.  Also invalidate
 * any corresponding untracked cache directory structures. Optimized to only
 * run the first time it is called.
 */
void refresh_fsmonitor(struct index_state *istate);

/*
 * Set the given cache entries CE_FSMONITOR_VALID bit. This should be
 * called any time the cache entry has been updated to reflect the
 * current state of the file on disk.
 */
static inline void mark_fsmonitor_valid(struct index_state *istate, struct cache_entry *ce)
{
	if (core_fsmonitor && !(ce->ce_flags & CE_FSMONITOR_VALID)) {
		istate->cache_changed = 1;
		ce->ce_flags |= CE_FSMONITOR_VALID;
		trace_printf_key(&trace_fsmonitor, "mark_fsmonitor_clean '%s'", ce->name);
	}
}

/*
 * Clear the given cache entry's CE_FSMONITOR_VALID bit and invalidate
 * any corresponding untracked cache directory structures. This should
 * be called any time git creates or modifies a file that should
 * trigger an lstat() or invalidate the untracked cache for the
 * corresponding directory
 */
static inline void mark_fsmonitor_invalid(struct index_state *istate, struct cache_entry *ce)
{
	if (core_fsmonitor) {
		ce->ce_flags &= ~CE_FSMONITOR_VALID;
		untracked_cache_invalidate_path(istate, ce->name, 1);
		trace_printf_key(&trace_fsmonitor, "mark_fsmonitor_invalid '%s'", ce->name);
	}
}

#ifdef HAVE_FSMONITOR_DAEMON_BACKEND
#include "thread-utils.h"

extern const char *git_path_fsmonitor(void);
#define FSMONITOR_VERSION 1ul

int fsmonitor_stop_daemon(void);
int fsmonitor_query_daemon(const char *since, struct strbuf *answer);
int fsmonitor_daemon_is_running(void);
int fsmonitor_spawn_daemon(void);

/* Internal fsmonitor */
struct fsmonitor_path {
	struct hashmap_entry entry;
	const char *path;
	size_t len;
	uint64_t time;
	enum {
		PATH_IS_UNSPECIFIED = -1,
		PATH_DOES_NOT_EXIST,
		PATH_IS_FILE,
		PATH_IS_DIRECTORY,
	} mode;
};

struct fsmonitor_queue_item {
	struct fsmonitor_path *path;
	uint64_t time;
	struct fsmonitor_queue_item *previous, *next;
};

struct fsmonitor_daemon_state {
	struct hashmap paths;
	struct fsmonitor_queue_item *first;
	struct fsmonitor_queue_item *last;
	uint64_t latest_update;
	pthread_mutex_t queue_update_lock, initial_mutex;
	pthread_cond_t initial_cond;
	int initialized;
	int error_code;
};

/*
 * Register a path as having been touched at a certain time.
 */
int fsmonitor_queue_path(struct fsmonitor_daemon_state *state,
			 struct fsmonitor_queue_item **queue,
			 const char *path, size_t len, uint64_t time);

/* This needs to be implemented by the backend */
struct fsmonitor_daemon_state *fsmonitor_listen(struct fsmonitor_daemon_state *state);
#endif

#endif
