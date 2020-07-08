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

static enum ipc_active_state get_active_state(wchar_t *pipe_path)
{
	if (WaitNamedPipeW(pipe_path, NMPWAIT_USE_DEFAULT_WAIT))
		return IPC_STATE__LISTENING;

	if (GetLastError() == ERROR_SEM_TIMEOUT)
		return IPC_STATE__NOT_LISTENING;

	if (GetLastError() == ERROR_FILE_NOT_FOUND)
		return IPC_STATE__PATH_NOT_FOUND;

	return IPC_STATE__OTHER_ERROR;
}

enum ipc_active_state ipc_get_active_state(const char *path)
{
	wchar_t pipe_path[MAX_PATH];

	if (initialize_pipe_name(path, pipe_path, ARRAY_SIZE(pipe_path)) < 0)
		return IPC_STATE__INVALID_PATH;

	return get_active_state(pipe_path);
}

#define WAIT_STEP_MS (50)

static enum ipc_active_state connect_to_server(
	const wchar_t *wpath,
	DWORD timeout_ms,
	const struct ipc_client_connect_options *options,
	int *pfd)
{
	DWORD t_start_ms, t_waited_ms;
	DWORD step_ms;
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	DWORD mode = PIPE_READMODE_BYTE;
	DWORD gle;

	*pfd = -1;

	while (1) {
		hPipe = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE,
				    0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		gle = GetLastError();

		trace2_data_intmax("ipc-client", NULL, "connect/result-gle",
				   gle);

		switch (gle) {
		case ERROR_FILE_NOT_FOUND:
			if (!options->wait_if_not_found)
				return IPC_STATE__PATH_NOT_FOUND;
			if (!timeout_ms)
				return IPC_STATE__PATH_NOT_FOUND;

			step_ms = (timeout_ms < WAIT_STEP_MS) ?
				timeout_ms : WAIT_STEP_MS;
			sleep_millisec(step_ms);

			timeout_ms -= step_ms;
			break; /* try again */

		case ERROR_PIPE_BUSY:
			if (!options->wait_if_busy)
				return IPC_STATE__NOT_LISTENING;
			if (!timeout_ms)
				return IPC_STATE__NOT_LISTENING;

			t_start_ms = (DWORD)(getnanotime() / 1000000);

			if (!WaitNamedPipeW(wpath, timeout_ms)) {
				if (GetLastError() == ERROR_SEM_TIMEOUT)
					return IPC_STATE__NOT_LISTENING;

				return IPC_STATE__OTHER_ERROR;
			}

			/*
			 * A pipe server instance became available.
			 * Race other client processes to connect to
			 * it.
			 *
			 * But first decrement our overall timeout so
			 * that we don't starve if we keep losing the
			 * race.  But also guard against special
			 * NPMWAIT_ values (0 and -1).
			 */
			t_waited_ms = (DWORD)(getnanotime() / 1000000) - t_start_ms;
			if (t_waited_ms < timeout_ms)
				timeout_ms -= t_waited_ms;
			else
				timeout_ms = 1;
			break; /* try again */

		default:
			return IPC_STATE__OTHER_ERROR;
		}
	}

	if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
		CloseHandle(hPipe);
		return IPC_STATE__OTHER_ERROR;
	}

	*pfd = _open_osfhandle((intptr_t)hPipe, O_RDWR|O_BINARY);
	if (*pfd < 0) {
		CloseHandle(hPipe);
		return IPC_STATE__OTHER_ERROR;
	}

	/* fd now owns hPipe */

	return IPC_STATE__LISTENING;
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

enum ipc_active_state ipc_client_try_connect(
	const char *path,
	const struct ipc_client_connect_options *options,
	int *pfd)
{
	wchar_t wpath[MAX_PATH];
	enum ipc_active_state state = IPC_STATE__OTHER_ERROR;

	*pfd = -1;

	trace2_region_enter("ipc-client", "try-connect", NULL);
	trace2_data_string("ipc-client", NULL, "try-connect/path", path);

	if (initialize_pipe_name(path, wpath, ARRAY_SIZE(wpath)) < 0)
		state = IPC_STATE__INVALID_PATH;
	else
		state = connect_to_server(wpath, WINDOWS_CONNECTION_TIMEOUT_MS,
					  options, pfd);

	trace2_data_intmax("ipc-client", NULL, "try-connect/state",
			   (intmax_t)state);
	trace2_region_leave("ipc-client", "try-connect", NULL);
	return state;
}

int ipc_client_send_command_to_fd(int fd, const char *message,
				  struct strbuf *answer)
{
	int ret = 0;

	strbuf_setlen(answer, 0);

	trace2_region_enter("ipc-client", "send-command", NULL);
	trace2_data_string("ipc-client", NULL, "command", message);

	if (write_packetized_from_buf(message, strlen(message), fd, 1) < 0) {
		ret = error(_("could not send IPC command"));
		goto done;
	}

	FlushFileBuffers((HANDLE)_get_osfhandle(fd));

	if (read_packetized_to_strbuf(fd, answer, PACKET_READ_NEVER_DIE) < 0) {
		ret = error(_("could not read IPC response"));
		goto done;
	}

	trace2_data_intmax("ipc-client", NULL, "response-length", answer->len);

done:
	trace2_region_leave("ipc-client", "send-command", NULL);
	return ret;
}

int ipc_client_send_command(const char *path,
			    const struct ipc_client_connect_options *options,
			    const char *message, struct strbuf *response)
{
	int fd;
	int ret = -1;
	enum ipc_active_state state;

	state = ipc_client_try_connect(path, options, &fd);

	if (state != IPC_STATE__LISTENING)
		return ret;

	ret = ipc_client_send_command_to_fd(fd, message, response);
	close(fd);
	return ret;
}

#endif /* GIT_WINDOWS_NATIVE */
