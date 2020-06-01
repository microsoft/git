#include "cache.h"
#include "fsmonitor.h"
#include <sys/inotify.h>
#include "khash.h"

KHASH_INIT(path2wd, const char *, int, 1, kh_str_hash_func, kh_str_hash_equal);
#define kh_int_hash_func(ey) key
#define kh_int_hash_equal(a, b) ((a) == (b))
KHASH_INIT(wd2path, int, const char *, 1, kh_int_hash_func, kh_int_hash_equal);

struct backend_data {
	int fd;
	kh_path2wd_t *path2wd;
	kh_wd2path_t *wd2path;
};

static int watch_directory(struct fsmonitor_daemon_state *state,
			   const char *path)
{
	uint32_t mask = IN_CLOSE_WRITE | IN_CREATE |
		IN_DELETE | IN_DELETE_SELF | IN_MODIFY |
		IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO;
	struct backend_data *data = state->backend_data;
	int wd = inotify_add_watch(data->fd, *path ? path : ".", mask);
	int ret1, ret2;
	khint_t pos1, pos2;

	if (wd < 0)
		return error_errno(_("could not watch '%s'"), path);

	pos1 = kh_put_path2wd(data->path2wd, path, &ret1);
	pos2 = kh_put_wd2path(data->wd2path, wd, &ret2);

	if (pos1 < kh_end(data->path2wd) &&
		pos2 < kh_end(data->wd2path)) {
		path = xstrdup(path);
		kh_key(data->path2wd, pos1) = path;
		kh_value(data->path2wd, pos1) = wd;
		kh_key(data->wd2path, pos2) = wd;
		kh_value(data->wd2path, pos2) = path;
	} else {
		if (pos1)
			kh_del_path2wd(data->path2wd, pos1);
		if (pos2)
			kh_del_wd2path(data->wd2path, pos2);
		inotify_rm_watch(data->fd, wd);
		return error(_("could not watch '%s"), path);
	}

	return wd;
}

static int watch_directory_recursively(struct fsmonitor_daemon_state *state,
				       struct strbuf *path)
{
	DIR *dir;
	struct dirent *de;

	if (!(dir = opendir(path->len ? path->buf : ".")))
		return error_errno(_("could not open directory '%s'"),
				   path->buf);

	if (watch_directory(state, path->buf) < 0) {
		int save_errno = errno;

		closedir(dir);
		errno = save_errno;
		return error_errno(_("failed to watch '%s'"), path->buf);
	}

	/* Do not watch anything inside the .git/ directory */
	if (!strcmp(".git/", path->buf)) {
		closedir(dir);
		return 0;
	}

	while ((de = readdir(dir))) {
		if (de->d_type == DT_DIR) {
			size_t save = path->len;

			if (!strcmp(de->d_name, ".") ||
			    !strcmp(de->d_name, ".."))
				continue;

			strbuf_addstr(path, de->d_name);
			strbuf_complete(path, '/');
			if (watch_directory_recursively(state, path) < 0)
				return -1;
			strbuf_setlen(path, save);
		}
	}

	closedir(dir);

	return 0;
}

static int unwatch_directory(struct fsmonitor_daemon_state *state,
			     const char *path)
{
	struct backend_data *data = state->backend_data;
	khint_t pos = kh_get_path2wd(data->path2wd, path);

	if (pos < kh_end(data->path2wd)) {
		int wd = kh_value(data->path2wd, pos);
		khint_t pos2 = kh_get_wd2path(data->wd2path, wd);

		free((char *)kh_key(data->path2wd, pos));
		kh_del_path2wd(data->path2wd, pos);
		if (pos2 < kh_end(data->wd2path))
			kh_del_wd2path(data->wd2path, pos2);
		return inotify_rm_watch(data->fd, wd);
	}

	return 0; /* ignore unseen path */
}

struct fsmonitor_daemon_state *fsmonitor_listen(
		struct fsmonitor_daemon_state *state)
{
	uint32_t deleted = IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM;
	uint32_t dir_created = IN_CREATE | IN_ISDIR;
	uint32_t dir_deleted = IN_DELETE | IN_ISDIR;
	struct strbuf buf = STRBUF_INIT;
	struct backend_data data;
	int ret;

	trace2_region_enter("fsmonitor", "inotify", the_repository);

	data.fd = inotify_init();
	if (data.fd < 0) {
		error_errno(_("could not initialize inotify"));
		trace2_region_leave("fsmonitor", "inotify", the_repository);
		return state;
	}

	data.path2wd = kh_init_path2wd();
	data.wd2path = kh_init_wd2path();
	state->backend_data = &data;

	ret = watch_directory_recursively(state, &buf);
	if (ret < 0) {
		error_errno(_("could not watch '.'"));
		strbuf_release(&buf);
		trace2_region_leave("fsmonitor", "inotify", the_repository);
		return state;
	}

	trace2_printf("Start watching: '%s' for inotify", get_git_work_tree());

	pthread_mutex_lock(&state->initial_mutex);
	state->latest_update = getnanotime();
	state->initialized = 1;
	pthread_cond_signal(&state->initial_cond);
	pthread_mutex_unlock(&state->initial_mutex);

	while (data.fd >= 0) {
		struct fsmonitor_queue_item dummy, *queue = &dummy;
		uint64_t time = getnanotime();
		char b[sizeof(struct inotify_event) + NAME_MAX + 1], *p;
		int ret = read(data.fd, &b, sizeof(b)), i;

		if (ret < 0) {
			error_errno(_("could not read() inotify fd"));
			goto out;
		}

		/* Ensure strictly increasing timestamps */
		pthread_mutex_lock(&state->queue_update_lock);
		if (time <= state->latest_update)
			time = state->latest_update + 1;
		pthread_mutex_unlock(&state->queue_update_lock);

		for (p = b; ret > 0; ) {
			const struct inotify_event *e = (void *)p;
			size_t incr = sizeof(struct inotify_event) + e->len;
			int special;
			khint_t pos;

			p += incr;
			ret -= incr;

			if (!e->len)
				continue;

			pos = kh_get_wd2path(data.wd2path, e->wd);
			if (!pos)
				continue;

			strbuf_reset(&buf);
			strbuf_addf(&buf, "%s%s", kh_value(data.wd2path, pos),
				    e->name);

			if ((e->mask & dir_created) == dir_created) {
				strbuf_complete(&buf, '/');
				if (watch_directory(state, buf.buf) < 0)
					goto out;
			}

			if ((e->mask & dir_deleted) == dir_deleted) {
				if (unwatch_directory(state, buf.buf) < 0) {
					error_errno(_("could not unwatch '%s'"),
						    buf.buf);
					goto out;
				}
			}

			special = fsmonitor_special_path(
				state, buf.buf, buf.len, e->mask & deleted);

			if (!special &&
			    fsmonitor_queue_path(state, &queue, buf.buf,
						 buf.len, time) < 0) {
				state->error_code = -1;
				error("could not queue '%s'; exiting", buf.buf);
				goto out;
			} else if (special == FSMONITOR_DAEMON_QUIT) {
				trace2_region_leave("fsmonitor", "inotify",
						    the_repository);
				trace2_data_string(
					"fsmonitor", the_repository, "message",
					".git directory was removed; quitting");
				exit(0);
			} else if (special < 0) {
				error(_("problem with path '%s'"), buf.buf);
				goto out;
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

		for (i = 0; i < state->cookie_list.nr; i++) {
			fsmonitor_cookie_seen_trigger(state, state->cookie_list.items[i].string);
		}

		string_list_clear(&state->cookie_list, 0);
	}

out:
	if (kh_size(data.path2wd) > 0) {
		const char *path;
		int wd;

		kh_foreach(data.path2wd, path, wd, {
			free((char *)path);
			if (data.fd >= 0)
				inotify_rm_watch(data.fd, wd);
		});
	}
	kh_release_path2wd(data.path2wd);
	kh_release_wd2path(data.wd2path);
	if (data.fd >= 0) {
		close(data.fd);
		data.fd = -1;
	}
	strbuf_release(&buf);
	fsmonitor_listen_stop(state);
	trace2_region_leave("fsmonitor", "inotify", the_repository);
	return state;
}

int fsmonitor_listen_stop(struct fsmonitor_daemon_state *state)
{
	struct backend_data *data = state->backend_data;

	error(_("fsmonitor was told to stop"));
	close(data->fd);
	data->fd = -1;

	return 0;
}
