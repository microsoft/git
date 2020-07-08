#include "cache.h"
#include "simple-ipc.h"
#include "strbuf.h"
#include "pkt-line.h"
#include "thread-utils.h"

#ifdef GIT_WINDOWS_NATIVE

static int initialize_pipe_name(const char *path, wchar_t *wpath, size_t alloc)
{
	int off = 0;
	struct strbuf realpath = STRBUF_INIT;

	if (!strbuf_realpath(&realpath, path, 0))
		return -1;

	off = swprintf(wpath, alloc, L"\\\\.\\pipe\\");
	if (xutftowcs(wpath + off, realpath.buf, alloc - off) < 0)
		return -1;

	/* Handle drive prefix */
	if (wpath[off] && wpath[off + 1] == L':') {
		wpath[off + 1] = L'_';
		off += 2;
	}

	for (; wpath[off]; off++)
		if (wpath[off] == L'/')
			wpath[off] = L'\\';

	strbuf_release(&realpath);
	return 0;
}

/*
 * TODO Would this be clearer if it was:
 * TODO    return (WaitNamedPipeW() || GetLastError() == ERROR_SEM_TIMEOUT);
 */
static enum IPC_ACTIVE_STATE is_active(wchar_t *pipe_path)
{
	if (WaitNamedPipeW(pipe_path, 1) ||
	    GetLastError() != ERROR_FILE_NOT_FOUND)
		return IPC_STATE__ACTIVE;
	else
		return IPC_STATE__NOT_ACTIVE;
}

enum IPC_ACTIVE_STATE ipc_is_active(const char *path)
{
	wchar_t pipe_path[MAX_PATH];

	if (initialize_pipe_name(path, pipe_path, ARRAY_SIZE(pipe_path)) < 0)
		return IPC_STATE__INVALID_PATH;

	return is_active(pipe_path);
}

static int connect_to_server(const char *path, const wchar_t *wpath,
			     DWORD timeout_ms, HANDLE *phPipe)
{
	DWORD t_start_ms, t_waited_ms;

	while (1) {
		*phPipe  = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE,
				       0, NULL, OPEN_EXISTING, 0, NULL);
		if (*phPipe != INVALID_HANDLE_VALUE)
			return 0;

		if (GetLastError() != ERROR_PIPE_BUSY) {
			/*
			 * We expect ERROR_FILE_NOT_FOUND when the server is not
			 * running, but other errors are possible here.
			 */
			return error(_("could not open pipe '%s' (gle %ld)"),
				     path, GetLastError());
		}

		t_start_ms = (DWORD)(getnanotime() / 1000000);

		if (!WaitNamedPipeW(wpath, timeout_ms)) {
			if (GetLastError() == ERROR_SEM_TIMEOUT)
				return error(_("pipe is busy '%s'"), path);

			return error(_("could not open '%s' (gle %ld)"),
				     path, GetLastError());
		}

		/*
		 * A pipe server instance became available.  Race other client
		 * processes to connect to it.
		 *
		 * But first decrement our overall timeout so that we don't
		 * starve if we keep losing the race.  But also guard against
		 * special NPMWAIT_ values (0 and -1).
		 */
		t_waited_ms = (DWORD)(getnanotime() / 1000000) - t_start_ms;

		timeout_ms -= t_waited_ms;
		if (timeout_ms < 1)
			timeout_ms = 1;
	}
}

/*
 * The default connection timeout for Windows clients.
 *
 * This is not currently part of the ipc_ API (nor the config settings)
 * because of differences between Windows and other platforms.
 *
 * This value was chosen at random.
 */
#define WINDOWS_CONNECTION_TIMEOUT_MS (30000)

int ipc_client_send_command(const char *path, const char *message,
			    struct strbuf *answer)
{
	wchar_t wpath[MAX_PATH];
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	DWORD mode = PIPE_READMODE_BYTE;
	int fd = -1;

	strbuf_setlen(answer, 0);

	if (initialize_pipe_name(path, wpath, ARRAY_SIZE(wpath)) < 0)
		return error(
			_("could not create normalized wchar_t path for '%s'"),
			path);

	if (connect_to_server(path, wpath, WINDOWS_CONNECTION_TIMEOUT_MS,
			      &hPipe))
		return -1;

	if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
		CloseHandle(hPipe);
		return error(_("could not switch pipe to byte mode '%s'"),
			     path);
	}

	fd = _open_osfhandle((intptr_t)hPipe, O_RDWR|O_BINARY);
	if (fd < 0) {
		CloseHandle(hPipe);
		return error(_("could not create fd for pipe handle '%s'"),
			     path);
	}

	hPipe = INVALID_HANDLE_VALUE; /* fd owns it now */

	if (write_packetized_from_buf(message, strlen(message), fd, 1) < 0) {
		close(fd);
		return error(_("could not send IPC to '%s'"), path);
	}

	FlushFileBuffers((HANDLE)_get_osfhandle(fd));

	if (read_packetized_to_strbuf(fd, answer, PACKET_READ_NEVER_DIE) < 0) {
		close(fd);
		return error(_("could not read IPC response from '%s'"), path);
	}

	close(fd);
	return 0;
}

#endif /* GIT_WINDOWS_NATIVE */
