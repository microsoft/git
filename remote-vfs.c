// TODO Write a man page.  Here are some notes for dogfooding.
// TODO
//
// Usage: git remote-vfs [<main_options>] <sub-command> [<sub-command-options>]
//
// <main_options>:
//
//     --remote=<remote-name>         // defaults to "origin"
//
//     --mode=<mode>                  // defaults to "auto"
//
//            auto    := auto-detect whether repo is VFS4G or Scalar mode.
//            vfs     := force VFS4G mode.
//            scalar  := force Scalar mode.
//            none    := assume neither mode.
//
//            The <mode> is used to look for mode-specific config settings:
//            "<mode>.cache-server" and "core.<mode>".
//
//            The <mode> is also used to find the mode-specific ODB:
//            <home-or-root-dir>/.<mode>Cache".
//
//            When <mode> is "auto", we look for the above for both products
//            and select whichever one we find.  If both products have values
//            defined, we complain.
//
//            When <mode> is "none", we assume no cache-server and use the
//            ".git/objects" ODB.
//
//     --fallback                     // boolean. defaults to off
//
//            When a fetch from the cache-server fails, automatically
//            fallback to the main Git server.  This option has no effect
//            if no cache-server is defined.
//
// <sub-command>:
//
//     config
//
//            Fetch the "gvfs/config" string from the main Git server.
//
//     get-missing
//
//            Fetch 1 or more "missing" objects.  If a cache-server is
//            configured, try it first.  Optionally fallback to the main
//            Git server.
//
//            The set of objects is given on stdin and is assumed to be
//            in rev-list format with the "--missing=print" option that
//            causes missing objects to print as "?<oid>"; other objects
//            in the rev-list output are ignored.  [I'll have another
//            verb later that takes a positive list of objects.]
//
//            [Currently] these objects will be requested in a single
//            batch fetch to the "gvfs/objects" endpoint.  If more than
//            one object is requested, a packfile will be created in the
//            chosen ODB with a "vfs-<date>.{pack|idx}" style name.
//            If only one object is requested, a loose object will be
//            created (this is a limitation of the GVFS Protocol).
//
//            [Currently] no progress is printed.
//            [Currently] no chunking is done.
//
//            <get-missing-options>:
//
//                 --depth=<depth>       // defaults to "1"
//
//                 --cache-server=<use>  // defaults to "verify"
//
//                       verify   := lookup the set of defined cache-servers
//                                   using "gvfs/config" and confirm that the
//                                   selected cache-server is well-known.
//                                   Silently disable the cache-server if not.
//                                   (See security notes later.)
//
//                       error    := verify cache-server and abort if not
//                                   well-known.
//
//                       allow    := do not verify cache-server.  just use it.
//
//                       disable  := disable the cache-server and always use
//                                   the main Git server.
//
// Example:
//
// $ git -c core.virtualizeobjects=false rev-list --objects --missing=print HEAD~1 >objects.list
// $ git remote-vfs get-missing <objects.list
//
// TODO In this version, we need to turn off "core.virtualizeobjects"
// TODO when building the list of objects to prevent rev-list from
// TODO automatically using read-object-hook on them individually
// TODO (and defeating the whole purpose of this transport).
//
// TODO [Currently] we get more credential dialogs than we should.
//////////////////////////////////////////////////////////////////

#include "cache.h"
#include "config.h"
#include "remote.h"
#include "connect.h"
#include "strbuf.h"
#include "walker.h"
#include "http.h"
#include "exec-cmd.h"
#include "run-command.h"
#include "pkt-line.h"
#include "string-list.h"
#include "sideband.h"
#include "argv-array.h"
#include "credential.h"
#include "sha1-array.h"
#include "send-pack.h"
#include "protocol.h"
#include "quote.h"
#include "transport.h"
#include "parse-options.h"
#include "object-store.h"
#include "json-writer.h"
#include "tempfile.h"
#include "oidset.h"

//////////////////////////////////////////////////////////////////

/* Additional error codes beyond HTTP_* in http.h */
#define RV_ERROR__USAGE                   -1
#define RV_ERROR__OK                      HTTP_OK
#define RV_ERROR__UNKNOWN_CACHE_SERVER    20
#define RV_ERROR__INDEX_PACK_FAILED       21
#define RV_ERROR__FINALIZE_FAILED         22
#define RV_ERROR__ERROR                   23 /* unspecified */
#define RV_ERROR__NOT_FOUND               24

static const char * const main_usage[] = {
	N_("git remote-vfs [<main_options>] config      [<options>]"),
	N_("git remote-vfs [<main_options>] get-missing [<options>]"),
	NULL
};

static const char *const get_missing_usage[] = {
	N_("git remote-vfs [<main_options>] get-missing [<options>]"),
	NULL
};

//////////////////////////////////////////////////////////////////

enum rv_mode {
	RV_MODE_AUTO = 0, /* auto-detect */
	RV_MODE_VFS,      /* force GVFS mode */
	RV_MODE_SCALAR,   /* force Scalar mode */
	RV_MODE_NONE,     /* disable product-specific caches */
};

enum rv_cache_server_use {
	RV_CSU_VERIFY_DISABLE = 0,  /* verify URL. disable if unknown. */
	RV_CSU_VERIFY_ERROR,        /* verify URL. error if unknown. */
	RV_CSU_DISABLE,             /* disable the cache-server, if defined */
	RV_CSU_ALLOW,               /* allow requests to any cache-server URL */
};

static struct rv_opts {
	const char *param__remote_name;

	const char *param__scalar_url; /* Scalar cache-server URL */
	const char *param__vfs_url;    /* VFS cache-server URL */

	const char *param__scalar_odb_path; /* .scalarCache path */
	const char *param__vfs_odb_path;    /* .gvfsCache path */

	int param__core_vfs;
	int param__core_scalar;

	int param__allow_fallback; /* to git server if cache-server fails */

	enum rv_mode param__mode;
	enum rv_cache_server_use param__csu;
} rv_opts;

static struct rv_data {
	struct remote *remote;

	struct credential main_creds;
	struct credential cache_creds;

	struct strbuf buf_main_url;
	struct strbuf buf_cache_server_url;

	struct strbuf buf_odb_path;

	enum rv_mode chosen_mode; /* excludes _AUTO */

	int http_is_initialized;
	int cache_server_is_initialized; /* did sub-command look for one */

} rv_data;

//////////////////////////////////////////////////////////////////

static int rest__get__gvfs_config(struct strbuf *result);

//////////////////////////////////////////////////////////////////

static int option_parse_mode(const struct option *opt,
			     const char *arg, int unset)
{
	if (unset) /* should not happen */
		return error(_("missing value for switch '%s'"),
			     opt->long_name);

	else if (!strcmp(arg, "auto"))
		rv_opts.param__mode = RV_MODE_AUTO;

	else if (!strcmp(arg, "vfs"))
		rv_opts.param__mode = RV_MODE_VFS;

	else if (!strcmp(arg, "scalar"))
		rv_opts.param__mode = RV_MODE_SCALAR;

	else if (!strcmp(arg, "none"))
		rv_opts.param__mode = RV_MODE_NONE;

	else
		return error(_("invalid value for switch '%s'"),
			     opt->long_name);

	return 0;
}

static int option_parse_csu(const struct option *opt,
			    const char *arg, int unset)
{
	if (unset) /* should not happen */
		return error(_("missing value for switch '%s'"),
			     opt->long_name);

	else if (!strcmp(arg, "verify"))
		rv_opts.param__csu = RV_CSU_VERIFY_DISABLE;

	else if (!strcmp(arg, "error"))
		rv_opts.param__csu = RV_CSU_VERIFY_ERROR;

	else if (!strcmp(arg, "disable"))
		rv_opts.param__csu = RV_CSU_DISABLE;

	else if (!strcmp(arg, "allow"))
		rv_opts.param__csu = RV_CSU_ALLOW;

	else
		return error(_("invalid value for switch '%s'"),
			     opt->long_name);

	return 0;
}

//////////////////////////////////////////////////////////////////

/*
 * The config is processed before we have parsed the command
 * line args so we don't yet know which (if any) cache-server
 * to use.  Remember both URLs and decide later.
 *
 * Also, look for well-known core config settings and capture
 * values.  We do this directly so that we don't have to know
 * about the existence of global variables from gvfs.c (or
 * later, scalar.c).
 *
 * Also, break from the traditional config-helper model and
 * do not intercept these values, but rather allow normal
 * config processing continue.
 */
static int config_cb(const char *k, const char *v, void *data)
{
	if (!strcmp(k, "gvfs.cache-server"))
		git_config_string(&rv_opts.param__vfs_url, k, v);

	else if (!strcmp(k, "scalar.cache-server"))
		git_config_string(&rv_opts.param__scalar_url, k, v);

	else if (!strcmp(k, "core.gvfs"))
		rv_opts.param__core_vfs = 1;

	else if (!strcmp(k, "core.scalar"))
		rv_opts.param__core_scalar = 1;

	return git_default_config(k, v, data);
}

//////////////////////////////////////////////////////////////////

/*
 * Find the path to the ".gvfsCache" or ".scalarCache" ODB directory.
 *
 * The local ODB for this repo is in ".git/objects/".
 *
 * GVFS and Scalar create a shared object cache somewhere near the root of
 * the drive.  This cache looks like a normal "alternate".
 *
 * Officially, the path to the shared cache is stored in the .gvfs folder
 * (and outside of the repo).  It is available from the "gvfs status" command.
 * Using it assumes our PATH is properly set up and we know which product's
 * command to run.
 */
static void lookup_odb_paths(void)
{
	struct object_directory *odb;

	prepare_alt_odb(the_repository);

	/*
	 * We now have a linked-list of ODBs.
	 *
	 * The first is always the local ODB (inside the .git directory).
	 * Then come the alternates.  We should only have 1 alternate, but
	 * can't complain if there are more.
	 */

	odb = the_repository->objects->odb;
	if (!odb)
		return;

	for (odb = odb->next; odb; odb = odb->next) {
		if (strstr(odb->path, ".gvfsCache"))
			rv_opts.param__vfs_odb_path = odb->path;

		else if (strstr(odb->path, ".scalarCache"))
			rv_opts.param__scalar_odb_path = odb->path;
	}
}

//////////////////////////////////////////////////////////////////

/*
 * Select the product-mode from the available inputs.  This resolves
 * the auto-detect case.  The chosen mode will be used later to select
 * the various product-specific caches -- or to disable them.
 */
static void choose_mode(void)
{
	switch (rv_opts.param__mode) {
	default: /* should not happen, but default to _AUTO. */
	case RV_MODE_AUTO:
	{
		int b_vfs = (rv_opts.param__core_vfs ||
			     rv_opts.param__vfs_url ||
			     rv_opts.param__vfs_odb_path);
		int b_scalar = (rv_opts.param__core_scalar ||
				rv_opts.param__scalar_url ||
				rv_opts.param__scalar_odb_path);

		if (b_vfs && b_scalar)
			die("Both VFS and Scalar found. Cannot auto choose.");

		if (b_vfs)
			rv_data.chosen_mode = RV_MODE_VFS;

		else if (b_scalar)
			rv_data.chosen_mode = RV_MODE_SCALAR;

		else
			rv_data.chosen_mode = RV_MODE_NONE;
		break;
	}
		
	case RV_MODE_VFS:
	case RV_MODE_SCALAR:
	case RV_MODE_NONE:
		rv_data.chosen_mode = rv_opts.param__mode;
		break;
	}
}

//////////////////////////////////////////////////////////////////

/*
 * We don't want to allow <user>@ or <user>:<pass>@ forms because
 * that shortcuts the credential manager (and we want it get us a
 * PAT), so return a version of the given url without those parts
 * (and without the complexity of url decoding and re-encoding).
 *
 * See "credential_from_url() in credential.c for details.
 */
static void strip_auth_from_url(struct strbuf *pbufout, const char *url)
{
	const char *at, *colon, *cp, *slash, *host, *proto_end;

	strbuf_setlen(pbufout, 0);

	/*
	 * Match one of:
	 *   (1) proto://<host>/...
	 *   (2) proto://<user>@<host>/...
	 *   (3) proto://<user>:<pass>@<host>/...
	 */
	proto_end = strstr(url, "://");
	if (!proto_end)
		return;
	cp = proto_end + 3;
	at = strchr(cp, '@');
	colon = strchr(cp, ':');
	slash = strchrnul(cp, '/');

	if (!at || slash <= at) {
		/* Case (1) */
		host = cp;
	}
	else if (!colon || at <= colon) {
		/* Case (2) */
		host = at + 1;
	} else {
		/* Case (3) */
		host = at + 1;
	}

	strbuf_add(pbufout, url, (cp - url));
	strbuf_addstr(pbufout, host);
}

/*
 * Lookup the URL for this remote (defaults to 'origin').
 */
static void lookup_main_url(void)
{
	/*
	 * Both VFS and Scalar only work with 'origin', so we expect this.
	 * The command line arg is mainly for debugging.
	 */
	if (!rv_opts.param__remote_name || !*rv_opts.param__remote_name)
		rv_opts.param__remote_name = "origin";

	rv_data.remote = remote_get(rv_opts.param__remote_name);
	if (!rv_data.remote->url[0] || !*rv_data.remote->url[0])
		die("unknown remote '%s'", rv_opts.param__remote_name);

	strbuf_init(&rv_data.buf_main_url, 0);

	/*
	 * Strip out any in-line auth in the origin server URL so that we
	 * can control which creds we fetch.
	 *
	 * For some reason some Azure DevOps repos suggest https URLS
	 * of the form "https://<account>@dev.azure.com/<account>/<path>".
	 *
	 * Break that so that we can force the use of a PAT.
	 */
	strip_auth_from_url(&rv_data.buf_main_url, rv_data.remote->url[0]);

	trace2_data_string("remote-vfs", NULL, "remote/url",
			   rv_data.buf_main_url.buf);
}

/*
 * GVFS cache-servers use the main Git server's creds rather than
 * having their own.  This feels like a security hole.  For example,
 * if the cache-server URL is pointed to a bad site, we'll happily
 * send them our creds for the main Git server with each request to
 * the cache-server.  This would allow an attacker to then use our
 * creds to impersonate us on the main Git server.
 *
 * Return HTTP_OK if the given URL is well-known.
 * Return HTTP_* or RV_ERROR_* for other errors.
 */
static int verify_cache_server_well_known_url(const char *p_url)
{
	struct strbuf result = STRBUF_INIT;
	struct strbuf pattern = STRBUF_INIT;
	int ret;

	ret = rest__get__gvfs_config(&result);
	if (ret != HTTP_OK)
		return ret;

	/*
	 * The gvfs/config response is in JSON, but I don't think
	 * we need to parse it and all that.  Lets just do a simple
	 * strstr() and assume it is sufficient.
	 *
	 * We do add some context to the pattern to guard against
	 * some attacks.
	 *
	 * TODO Consider using "\"Url\":\"%s\"" instead.
	 */

	strbuf_addf(&pattern, "\"%s\"", p_url);
	if (strstr(result.buf, pattern.buf))
		ret = HTTP_OK;
	else
		ret = RV_ERROR__UNKNOWN_CACHE_SERVER;

	strbuf_release(&pattern);
	strbuf_release(&result);

	return ret;
}

/*
 * Find the URL of the cache-server, if we have one.
 */
static void select_cache_server(void)
{
	const char *p_url = NULL;
	int ret = HTTP_OK;

	/*
	 * This only indicates that the sub-command actually called
	 * us.  We rely on rv_data.buf_cache_server_url.len to tell
	 * us if we actually have a cache-server configured.
	 */
	rv_data.cache_server_is_initialized = 1;

	strbuf_init(&rv_data.buf_cache_server_url, 0);
	if (rv_opts.param__csu == RV_CSU_DISABLE)
		return;

	switch (rv_data.chosen_mode) {
	default:            /* should not happen */
	case RV_MODE_AUTO:  /* should not happen */
	case RV_MODE_NONE:  /* no cache-server for us */
		return;

	case RV_MODE_VFS:
		if (!rv_opts.param__vfs_url)
			return;
		p_url = rv_opts.param__vfs_url;
		break;

	case RV_MODE_SCALAR:
		if (!rv_opts.param__scalar_url)
			return;
		p_url = rv_opts.param__scalar_url;
		break;
	}

	switch (rv_opts.param__csu) {
	default:             /* should not happen */
	case RV_CSU_VERIFY_ERROR:
		ret = verify_cache_server_well_known_url(p_url);
		if (ret != HTTP_OK)
			die("could not verify cache-server is well-known");
		break;

	case RV_CSU_VERIFY_DISABLE:
		ret = verify_cache_server_well_known_url(p_url);
		/*
		 * If not-known or error, just disable the cache-server
		 * and go on.
		 */
		if (ret != HTTP_OK)
			return;
		break;

	case RV_CSU_ALLOW:
		/*
		 * We allow anything in permissive mode.
		 */
		break;
	}

	/*
	 * There should not be any in-line auth in the cache-server
	 * URLs, but strip them out just in case.  We don't want the
	 * in-line values to overwrite the values we are forcing here.
	 */
	strip_auth_from_url(&rv_data.buf_cache_server_url, p_url);

	trace2_data_string("remote-vfs", NULL, "cache/url",
			   rv_data.buf_cache_server_url.buf);
}

//////////////////////////////////////////////////////////////////

/*
 * Read stdin until EOF (or a blank line) and add the desired OIDs
 * to the oidset.
 *
 * We expect stdin to contain output from a command like:
 * rev-list --objects [--missing=print] [--filter-print-omitted]
 *
 * Stdin should contain a list of OIDs.  It may have additional
 * decoration that we need to strip out.
 *
 * We expect:
 * <hex_oid> [<path>]   // present OIDs
 * ~<hex_oid>           // omitted OIDs
 * ?<hex_oid>           // missing OIDs
 *
 * Allowing this slightly "dirty" format saves us from having to
 * do something like "rev-list | grep | sed | remote-vfs".
 */
static int read_stdin_from_rev_list(struct oidset *oids, int b_missing_only)
{
	struct object_id oid;
	struct strbuf buf_stdin = STRBUF_INIT;
	int count = 0;

	do {
		const char *p = NULL;

		if (strbuf_getline(&buf_stdin, stdin) == EOF || !buf_stdin.len)
			break;

		if (buf_stdin.buf[0] == '?')
			p = buf_stdin.buf + 1;
		else if (b_missing_only)
			continue;
		else if (buf_stdin.buf[0] == '~')
			p = buf_stdin.buf + 1;
		else
			p = buf_stdin.buf;

		/*
		 * If this is a bogus OID (not a hex string), just eat it.
		 */
		if (get_oid_hex(p, &oid))
			continue;

		if (!oidset_insert(oids, &oid))
			count++;
	} while (1);

	return count;
}

/*
 * Build a complete JSON payload for a gvfs/objects POST request.
 *
 * https://github.com/microsoft/VFSForGit/blob/master/Protocol.md
 */
static void build_json_payload__gvfs_objects(struct json_writer *jw_req,
					     int depth,
					     struct oidset *oids)
{
	struct oidset_iter iter;
	const struct object_id *oid;

	oidset_iter_init(oids, &iter);

	jw_init(jw_req);
	jw_object_begin(jw_req, 0);
	jw_object_intmax(jw_req, "commitDepth", depth);
	jw_object_inline_begin_array(jw_req, "objectIds");
	while ((oid = oidset_iter_next(&iter)))
		jw_array_string(jw_req, oid_to_hex(oid));
	jw_end(jw_req);
	jw_end(jw_req);
}

//////////////////////////////////////////////////////////////////

/*
 * Lookup the creds for the main/origin Git server.
 *
 * Both VFS and Scalar always require authentication for both
 * the main Git server and the cache-server.  Furthermore, the
 * cache-server requires that we authenticate with the origin
 * Git server and use those creds.
 *
 * If we are requesting data from the main Git server, we don't
 * need to force a lookup now, since the normal 401 mechanism
 * will take care of it.
 *
 * However, if we are requesting data from the cache-server, we
 * need to pre-load the main creds and stuff them into the creds
 * for the cache-server, because the cache-server doesn't know
 * how to do the 401 thing.
 */
static void lookup_main_creds(void)
{
	if (rv_data.main_creds.username && *rv_data.main_creds.username)
		return;

	/*
	 * Preload the creds for the origin server to minimize the
	 * roundtrips.  We may revisit this later.
	 */
	credential_from_url(&rv_data.main_creds, rv_data.buf_main_url.buf);
	credential_fill(&rv_data.main_creds);

	// TODO consider deleting this message.
	trace2_printf("remote_cred [host '%s'][user '%s']",
		      rv_data.main_creds.host,
		      rv_data.main_creds.username ?
		      rv_data.main_creds.username : "");
}

/*
 * Tell the credential manager to throw away the creds for the main
 * Git server and ask it to reacquire them.
 */
static void refresh_main_creds(void)
{
	credential_reject(&rv_data.main_creds);
	lookup_main_creds();

	// TODO should we compare before and after values of u/p and
	// TODO shortcut reauth if we already know it will fail?
	// TODO if so, return a bool if same/different.
}

/*
 * Build a set of creds for the cache-server based upon the main Git
 * server (assuming we have a cache-server configured).
 */
static void synthesize_cache_server_creds(void)
{
	if (!rv_data.cache_server_is_initialized)
		BUG("sub-command did not initialize cache-server vars");

	if (!rv_data.buf_cache_server_url.len)
		return;

	if (rv_data.cache_creds.username && *rv_data.cache_creds.username)
		return;

	/*
	 * Get the main Git server creds so we can borrow the username
	 * and password when we talk to the cache-server.
	 */
	lookup_main_creds();

	// TODO we might not need to fully populate the creds for the
	// TODO cache-server if we can completely disable the "store" and
	// TODO "reject" events (in http.c) after the http request returns.
	// TODO And if we can prevent a config scan.

	credential_from_url(&rv_data.cache_creds,
			    rv_data.buf_cache_server_url.buf);
	rv_data.cache_creds.username = xstrdup(rv_data.main_creds.username);
	rv_data.cache_creds.password = xstrdup(rv_data.main_creds.password);

	// TODO consider deleting this message.
	trace2_printf("cache_cred [host '%s'][user '%s']",
		      rv_data.cache_creds.host,
		      rv_data.cache_creds.username ?
		      rv_data.cache_creds.username : "");
}

/*
 * Flush and refresh the cache-server creds.  Because the cache-server
 * does not do 401s (or manage creds), we have to reload the main Git
 * server creds first.
 */
static void refresh_cache_server_creds(void)
{
	credential_clear(&rv_data.cache_creds);

	refresh_main_creds();
	synthesize_cache_server_creds();
}

//////////////////////////////////////////////////////////////////

/*
 * Select the ODB directory where we will write objects that we
 * download.  If no product-specific ODB is defined, use the
 * local ODB (in ".git/objects").
 */
static void select_odb(void)
{
	const char *p_odb = the_repository->objects->odb->path;

	strbuf_init(&rv_data.buf_odb_path, 0);

	switch (rv_data.chosen_mode) {
	default:            /* should not happen */
	case RV_MODE_AUTO:  /* should not happen */
	case RV_MODE_NONE:
		break;

	case RV_MODE_VFS:
		if (rv_opts.param__vfs_odb_path)
			p_odb = rv_opts.param__vfs_odb_path;
		break;

	case RV_MODE_SCALAR:
		if (rv_opts.param__scalar_odb_path)
			p_odb = rv_opts.param__scalar_odb_path;
		break;
	}

	strbuf_addstr(&rv_data.buf_odb_path, p_odb);
}

/*
 * Create a tempfile to stream the packfile into.
 *
 * We create a tempfile in the chosen ODB directory and let CURL
 * automatically stream data to the file.  If successful, we can
 * later rename it to a proper .pack and run "git index-pack" on
 * it to create the corresponding .idx file.
 *
 * NOTE: I would rather to just stream the packfile directly into
 * "git index-pack --stdin" (and save some I/O) because it will
 * automatically take care of the rename of both files and any
 * other cleanup.  But index-pack will only write to the primary
 * ODB -- it will not write into the alternates (this is considered
 * bad form).  So we would need to add an option to index-pack to
 * handle this.  I don't want to deal with this issue right now.
 */
static struct tempfile *create_tempfile_for_packfile(void)
{
	struct timeval tv;
	struct tm tm;
	time_t secs;
	char tbuf[32];
	struct tempfile *tempfile = NULL;
	struct strbuf buf_path = STRBUF_INIT;

	gettimeofday(&tv, NULL);
	secs = tv.tv_sec;
	gmtime_r(&secs, &tm);

	xsnprintf(tbuf, sizeof(tbuf), "%4d%02d%02dT%02d%02d%02dZ",
		  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		  tm.tm_hour, tm.tm_min, tm.tm_sec);

	// TODO should this be in the "<ODB>/pack/tempPacks/"
	// TODO directory instead?

	strbuf_addbuf(&buf_path, &rv_data.buf_odb_path);
	strbuf_complete(&buf_path, '/');
	strbuf_addf(&buf_path, "pack/vfs-%s.temp", tbuf);

	tempfile = create_tempfile(buf_path.buf);
	fdopen_tempfile(tempfile, "w");

	strbuf_release(&buf_path);

	return tempfile;
}

/*
 * Create a tempfile to stream a loose object into.
 *
 * We create a tempfile in the chosen ODB directory and let CURL
 * automatically stream data to the file.
 */
static struct tempfile *create_tempfile_for_loose(const struct object_id *oid)
{
	struct tempfile *tempfile = NULL;
	struct strbuf buf_path = STRBUF_INIT;
	const char *hex;

	hex = oid_to_hex(oid);

	strbuf_addbuf(&buf_path, &rv_data.buf_odb_path);
	strbuf_complete(&buf_path, '/');
	strbuf_add(&buf_path, hex, 2);
	strbuf_addch(&buf_path, '/');
	strbuf_addstr(&buf_path, hex+2);
	strbuf_addstr(&buf_path, ".temp");

	tempfile = create_tempfile(buf_path.buf);
	fdopen_tempfile(tempfile, "w");

	strbuf_release(&buf_path);

	return tempfile;
}

/*
 * Convert the tempfile into a permanent .pack packfile in the ODB.
 * Create the corresponding .idx file.
 *
 * Return the full pathname of the resulting packfile.
 */
static void install_packfile(struct tempfile **pp_tempfile,
			     struct strbuf *packfile_name)
{
	struct child_process ip = CHILD_PROCESS_INIT;
	struct strbuf pack_name_tmp = STRBUF_INIT;
	struct strbuf pack_name_dst = STRBUF_INIT;
	struct strbuf idx_name_tmp = STRBUF_INIT;
	struct strbuf idx_name_dst = STRBUF_INIT;
	size_t len_base;

	/*
	 * start with "<base>.temp" and owned by tempfile class.
	 * rename to "<base>.pack.temp" to break ownership.
	 * create "<base>.idx.temp" on provisional packfile.
	 * officially install both "<base>.*.temp" as "<base>.*".
	 */

	strbuf_addstr(&pack_name_tmp, get_tempfile_path(*pp_tempfile));
	if (!strip_suffix(pack_name_tmp.buf, ".temp", &len_base))
		BUG("packfile tempfile does not end in '.temp': '%s'",
		    pack_name_tmp.buf);

	strbuf_setlen(&pack_name_tmp, (int)len_base);
	strbuf_addbuf(&pack_name_dst, &pack_name_tmp);
	strbuf_addbuf(&idx_name_tmp, &pack_name_tmp);
	strbuf_addbuf(&idx_name_dst, &pack_name_tmp);

	strbuf_addstr(&pack_name_tmp, ".pack.temp");
	strbuf_addstr(&pack_name_dst, ".pack");
	strbuf_addstr(&idx_name_tmp, ".idx.temp");
	strbuf_addstr(&idx_name_dst, ".idx");

	// TODO if either pack_name_dst or idx_name_dst already
	// TODO exists in the ODB, create alternate names so that
	// TODO we don't step on them.

	if (rename_tempfile(pp_tempfile, pack_name_tmp.buf) == -1)
		die("could not rename packfile to '%s'", pack_name_tmp.buf);

	argv_array_push(&ip.args, "index-pack");
	argv_array_pushl(&ip.args, "-o", idx_name_tmp.buf, NULL);
	argv_array_push(&ip.args, pack_name_tmp.buf);
	ip.git_cmd = 1;
	ip.no_stdin = 1;
	ip.no_stdout = 1;

	// TODO consider capturing stdout from index-pack because
	// TODO it will contain the SHA of the packfile and we can
	// TODO (should?) add it to the .pack and .idx pathnames
	// TODO when we install them.
	// TODO
	// TODO Or should be SHA-it ourselves (or read the last 20 bytes)?

	if (run_command(&ip)) {
		unlink(pack_name_tmp.buf);
		unlink(idx_name_tmp.buf);
		die("index-pack failed on '%s'", pack_name_tmp.buf);
	}

	if (finalize_object_file(pack_name_tmp.buf, pack_name_dst.buf) ||
	    finalize_object_file(idx_name_tmp.buf, idx_name_dst.buf)) {
		unlink(pack_name_tmp.buf);
		unlink(pack_name_dst.buf);
		unlink(idx_name_tmp.buf);
		unlink(idx_name_dst.buf);
		die("could not install packfile '%s'", pack_name_dst.buf);
	}

	strbuf_setlen(packfile_name, 0);
	strbuf_addbuf(packfile_name, &pack_name_dst);

	child_process_clear(&ip);
	strbuf_release(&pack_name_tmp);
	strbuf_release(&pack_name_dst);
	strbuf_release(&idx_name_tmp);
	strbuf_release(&idx_name_dst);
}

/*
 * Convert the tempfile into a permanent loose object in the ODB.
 *
 * Return the full pathname of the resulting file.
 */
static void install_loose(struct tempfile **pp_tempfile,
			  struct strbuf *loose_path)
{
	struct strbuf loose_path_tmp = STRBUF_INIT;
	size_t len_base;

	/*
	 * start with "<odb>/xx/y38.temp" and owned by tempfile class.
	 * compute new name as "<odb>/xx/y38".
	 * close tempfile to steal ownership.
	 * officially install loose object.
	 */

	strbuf_addstr(&loose_path_tmp, get_tempfile_path(*pp_tempfile));
	close_tempfile_gently(*pp_tempfile);
	pp_tempfile = NULL;

	if (!strip_suffix(loose_path_tmp.buf, ".temp", &len_base))
		BUG("loose object tempfile does not end in '.temp': '%s'",
		    loose_path_tmp.buf);

	strbuf_setlen(loose_path, 0);
	strbuf_add(loose_path, loose_path_tmp.buf, len_base);

	if (finalize_object_file(loose_path_tmp.buf, loose_path->buf)) {
		unlink(loose_path_tmp.buf);
		die("could not install loose object '%s'", loose_path->buf);
	}

	strbuf_release(&loose_path_tmp);
}

//////////////////////////////////////////////////////////////////

/*
 * Our wrapper to initialize the HTTP layer.
 *
 * We always use the real origin server, not the cache-server.
 */
static void rv_http_init(void)
{
	if (rv_data.http_is_initialized)
		return;

	http_init(rv_data.remote, rv_data.buf_main_url.buf, 0);
	rv_data.http_is_initialized = 1;
}

static void rv_http_cleanup(void)
{
	if (!rv_data.http_is_initialized)
		return;

	http_cleanup();
	rv_data.http_is_initialized = 0;
}

//////////////////////////////////////////////////////////////////

/*
 * Send a GET request to either the cache-server or the main Git server.
 *
 * url_component contains something like "gvfs/objects" or "gvfs/config".
 *
 * Returns one of the HTTP_ values, like HTTP_OK.  (This is NOT the server
 * response code; those values are hidden inside http.c.)
 *
 * Also, populates the charset, mime-type, the content buffers.
 */
static int do_get__into_buffer(int b_use_cache_server,
			       const char *url_component,
			       struct strbuf *type,
			       struct strbuf *charset,
			       struct strbuf *buffer)
{
	struct string_list extra_headers = STRING_LIST_INIT_DUP;
	struct http_get_options http_options;
	struct strbuf rest_url = STRBUF_INIT;
	int ret = HTTP_OK;

	// TODO consider replacing call to http.c with direct calls
	// TODO to curl library (like I did for do_get__into_file())
	// TODO to avoid some of the credential complexity and possibly
	// TODO redundant calls.

	strbuf_init(type, 0);
	strbuf_init(charset, 0);
	strbuf_init(buffer, 0);

	/*
	 * Disable the 302 + 203 redirect sequence to a login page and force
	 * the main Git server to send a normal 401.
	 */
	string_list_append(&extra_headers, "X-TFS-FedAuthRedirect: Suppress");

	memset(&http_options, 0, sizeof(http_options));
	http_options.content_type = type;
	http_options.charset = charset;
	http_options.effective_url = NULL;
	http_options.base_url = NULL;
	http_options.extra_headers = &extra_headers;
	http_options.initial_request = 1;
	http_options.no_cache = 1;

	/*
	 * Force set the creds when talking to the cache-server.
	 *
	 * The http.c layer automatically handles the 401 retry and
	 * cred lookup logic for the main Git server, but cannot for
	 * the cache-server because the cache-server doesn't do 401s.
	 */
	if (b_use_cache_server) {
		synthesize_cache_server_creds();
		http_options.force_vfs_creds = &rv_data.cache_creds;
	}

	end_url_with_slash(&rest_url, (b_use_cache_server ?
				       rv_data.buf_cache_server_url.buf :
				       rv_data.buf_main_url.buf));
	strbuf_addstr(&rest_url, url_component);

	ret = http_get_strbuf(rest_url.buf, buffer, &http_options);

	// TODO free/release extra_headers?

	return ret;
}

#if 0
/*
 * Send a GET request to cache-server if present and fallback to the
 * main Git server if necessary.
 *
 * url_component contains something like "gvfs/objects" or "gvfs/config".
 */
static int do_get__into_buffer_with_fallback(const char *url_component,
					     struct strbuf *type,
					     struct strbuf *charset,
					     struct strbuf *buffer)
{
	int ret = HTTP_OK;

	if (rv_data.buf_cache_server_url.len) {
		ret = do_get__into_buffer(1, url_component,
					  type, charset, buffer);
		if (ret == HTTP_OK)
			return ret;

		if (!rv_opts.param__allow_fallback)
			return ret;
	}

	ret = do_get__into_buffer(0, url_component,
				  type, charset, buffer);

	return ret;
}
#endif

/*
 * Do a single GET (without retry or fallback).
 */
static int do_get__into_file(const char *url_base,
			     const char *url_component,
			     const struct credential *creds,
			     struct tempfile *tempfile,
			     long *http_response_code,
			     struct strbuf *error_message)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct curl_slist *headers = http_copy_default_headers();
	struct strbuf rest_url = STRBUF_INIT;
	int ret = HTTP_OK;

	end_url_with_slash(&rest_url, url_base);
	strbuf_addstr(&rest_url, url_component);

	headers = curl_slist_append(headers,
				    "X-TFS-FedAuthRedirect: Suppress");

	slot = get_active_slot();

	curl_easy_setopt(slot->curl, CURLOPT_URL, rest_url.buf);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEDATA, (void*)tempfile->fp);

	if (creds && creds->username) {
		/*
		 * Force CURL to respect the username/password we provide by
		 * turning off the AUTH-ANY negotiation stuff.
		 *
		 * (AUTH-ANY forces a 401 regardless of what we send).
		 */
		curl_easy_setopt(slot->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_easy_setopt(slot->curl, CURLOPT_USERNAME, creds->username);
		curl_easy_setopt(slot->curl, CURLOPT_PASSWORD, creds->password);
	} else {
		/*
		 * Turn on the AUTH-ANY negotiation.  This only works with the
		 * main Git server (because the cache-server doesn't handle 401s).
		 */
		curl_easy_setopt(slot->curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
	}

	ret = run_one_slot(slot, &results);
	curl_easy_getinfo(slot->curl, CURLINFO_RESPONSE_CODE,
			  http_response_code);

//	trace2_printf("GET: [ret %d] [http %ld] [curl %d '%s'] [res %ld]",
//		      ret, results.http_connectcode, results.curl_result,
//		      curl_easy_strerror(results.curl_result),
//		      *http_response_code);

	strbuf_setlen(error_message, 0);
	strbuf_addstr(error_message, curl_easy_strerror(results.curl_result));


	curl_slist_free_all(headers);

	return ret;
}

static int do_get__into_file__to_main(const char *url_component,
				      struct tempfile *tempfile,
				      struct strbuf *error_message)
{
	int ret = HTTP_OK;
	const struct credential *p_creds = NULL;
	long http_response_code;

	lookup_main_creds();

	if (rv_data.main_creds.username && *rv_data.main_creds.username)
		p_creds = &rv_data.main_creds;

	strbuf_setlen(error_message, 0);
	trace2_region_enter("remote-vfs", "GET/object/main1", NULL);
	ret = do_get__into_file(rv_data.buf_main_url.buf, url_component,
				p_creds, tempfile,
				&http_response_code, error_message);
	trace2_region_leave("remote-vfs", "GET/object/main1", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;

	if (ret != HTTP_REAUTH)
		return ret;

	refresh_main_creds();

	/*
	 * Since we are automatically retrying, truncate the error
	 * message from the first attempt.  The caller should only
	 * see the error message from the final attempt.
	 */
	strbuf_setlen(error_message, 0);

	// TODO ftruncate tempfile ??

	p_creds = &rv_data.main_creds;
	trace2_region_enter("remote-vfs", "GET/object/main2", NULL);
	ret = do_get__into_file(rv_data.buf_main_url.buf, url_component,
				p_creds, tempfile,
				&http_response_code, error_message);
	trace2_region_leave("remote-vfs", "GET/object/main2", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;
	return ret;
}

static int do_get__into_file__to_cache_server(const char *url_component,
					      struct tempfile *tempfile,
					      struct strbuf *error_message)
{
	long http_response_code;
	int ret = HTTP_OK;

	synthesize_cache_server_creds();

	strbuf_setlen(error_message, 0);
	trace2_region_enter("remote-vfs", "GET/object/cs1", NULL);
	ret = do_get__into_file(rv_data.buf_cache_server_url.buf,
				url_component, &rv_data.cache_creds,
				tempfile, &http_response_code, error_message);
	trace2_region_leave("remote-vfs", "GET/object/cs1", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;

	if (http_response_code == 404)
		return RV_ERROR__NOT_FOUND;

	if (http_response_code != 400)
		return RV_ERROR__ERROR;

	/* Assume a 400 is a virtual-401 and retry */

	refresh_cache_server_creds();

	strbuf_setlen(error_message, 0);

	// TODO ftruncate tempfile ??

	trace2_region_enter("remote-vfs", "GET/object/cs2", NULL);
	ret = do_get__into_file(rv_data.buf_cache_server_url.buf,
				url_component, &rv_data.cache_creds,
				tempfile, &http_response_code, error_message);
	trace2_region_leave("remote-vfs", "GET/object/cs2", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;

	if (http_response_code == 404)
		return RV_ERROR__NOT_FOUND;

	return ret;
}

static int do_get__into_file__with_fallback(const char *url_component,
					    struct tempfile *tempfile,
					    struct strbuf *error_message)
{
	int ret = HTTP_OK;

	if (rv_data.buf_cache_server_url.len) {
		ret = do_get__into_file__to_cache_server(
			url_component, tempfile, error_message);
		if (ret == HTTP_OK)
			return ret;

		if (!rv_opts.param__allow_fallback)
			return ret;
	}

	ret = do_get__into_file__to_main(url_component, tempfile,
					 error_message);
	if (ret == HTTP_OK)
		return HTTP_OK;
	return ret;
}

static int rest__get__into_file__gvfs_objects(const struct object_id *oid,
					      struct tempfile *tempfile,
					      struct strbuf *error_message)
{
	struct strbuf component_url = STRBUF_INIT;
	int ret = HTTP_OK;

	strbuf_addf(&component_url, "gvfs/objects/%s", oid_to_hex(oid));

	rv_http_init();

	trace2_region_enter("remote-vfs", "GET/gvfs/objects", NULL);
	ret = do_get__into_file__with_fallback(component_url.buf, tempfile,
					       error_message);
	trace2_data_intmax("remote-vfs", NULL, "GET/result", ret);
	trace2_region_leave("remote-vfs", "GET/gvfs/objects", NULL);

	rv_http_cleanup();

	return ret;
}

static void do__loose__gvfs_object(const struct object_id *oid,
				   struct strbuf *loose_path)
{
	struct tempfile *tempfile = NULL;
	struct strbuf error_message = STRBUF_INIT;
	int ret = HTTP_OK;

	tempfile = create_tempfile_for_loose(oid);

	ret = rest__get__into_file__gvfs_objects(oid, tempfile, &error_message);
	fflush(tempfile->fp);

	if (ret != HTTP_OK) {
		delete_tempfile(&tempfile);
		die("%s", error_message.buf);
	}

	strbuf_release(&error_message);

	install_loose(&tempfile, loose_path);
	tempfile = NULL;
}

//////////////////////////////////////////////////////////////////

/*
 * Send a "gvfs/config" REST request via HTTP GET.  We only send this
 * to the main Git server (because the cache-server doesn't support
 * the REST API).
 *
 * We only return the server response string.  Our caller must decide
 * what to do with it.
 */
static int rest__get__gvfs_config(struct strbuf *result)
{
	struct strbuf type = STRBUF_INIT;
	struct strbuf charset = STRBUF_INIT;
	int ret;

	strbuf_init(result, 0);

	rv_http_init();

	trace2_region_enter("remote-vfs", "gvfs/config", NULL);
	ret = do_get__into_buffer(0, "gvfs/config", &type, &charset, result);
	// TODO get error message from http.c layer and return to our caller
	trace2_region_leave("remote-vfs", "gvfs/config", NULL);

	rv_http_cleanup();

	strbuf_release(&charset); /* probably contains "utf-8" */
	strbuf_release(&type);    /* probably contains "application/json" */

	return ret;
}

//////////////////////////////////////////////////////////////////

/*
 * Stolen from http.c
 */
static CURLcode curlinfo_strbuf(CURL *curl, CURLINFO info, struct strbuf *buf)
{
	char *ptr;
	CURLcode ret;

	strbuf_reset(buf);
	ret = curl_easy_getinfo(curl, info, &ptr);
	if (!ret && ptr)
		strbuf_addstr(buf, ptr);
	return ret;
}

/*
 * Do a single POST (without retry or fallback) with the given payload.
 */
static int do_post(const char *url_base,
		   const char *url_component,
		   const struct credential *creds,
		   const struct strbuf *post_payload,
		   struct tempfile *tempfile,
		   struct strbuf *received_content_type,
		   long *http_response_code,
		   struct strbuf *error_message)
{
	struct active_request_slot *slot;
	struct slot_results results;
	struct curl_slist *headers = http_copy_default_headers();
	struct strbuf rest_url = STRBUF_INIT;
	int ret = HTTP_OK;

	end_url_with_slash(&rest_url, url_base);
	strbuf_addstr(&rest_url, url_component);

	headers = curl_slist_append(headers,
				    "X-TFS-FedAuthRedirect: Suppress");

	headers = curl_slist_append(headers,
				    "Content-Type: application/json");

	/*
	 * We really always want a packfile.  But if the payload only
	 * requests 1 OID, the server will/may send us a single loose
	 * objects instead.  (Apparently the server ignores us when we
	 * only send application/x-git-packfile and does it anyway.)
	 *
	 * So to make it clear to my future self, go ahead and add
	 * an accept header for loose objects and own it.
	 */
	headers = curl_slist_append(headers,
				    "Accept: application/x-git-packfile");
	headers = curl_slist_append(headers,
				    "Accept: application/x-git-loose-object");

	slot = get_active_slot();

	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);
	curl_easy_setopt(slot->curl, CURLOPT_POST, 1);
	curl_easy_setopt(slot->curl, CURLOPT_URL, rest_url.buf);
	curl_easy_setopt(slot->curl, CURLOPT_ENCODING, NULL);
	curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDS, post_payload->buf);
	curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDSIZE, post_payload->len);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEDATA, (void*)tempfile->fp);

	if (creds && creds->username) {
		/*
		 * Force CURL to respect the username/password we provide by
		 * turning off the AUTH-ANY negotiation stuff.
		 *
		 * (AUTH-ANY forces a 401 regardless of what we send).
		 */
		curl_easy_setopt(slot->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_easy_setopt(slot->curl, CURLOPT_USERNAME, creds->username);
		curl_easy_setopt(slot->curl, CURLOPT_PASSWORD, creds->password);
	} else {
		/*
		 * Turn on the AUTH-ANY negotiation.  This only works with the
		 * main Git server (because the cache-server doesn't handle 401s).
		 */
		curl_easy_setopt(slot->curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
	}

	ret = run_one_slot(slot, &results);

	curlinfo_strbuf(slot->curl, CURLINFO_CONTENT_TYPE,
			received_content_type);
	curl_easy_getinfo(slot->curl, CURLINFO_RESPONSE_CODE,
			  http_response_code);

//	trace2_printf(
//		"POST: [ret %d] [http %ld] [curl %d '%s'] [ct '%s'] [res %ld]",
//		ret, results.http_connectcode, results.curl_result,
//		curl_easy_strerror(results.curl_result),
//		received_content_type->buf, *http_response_code);

	strbuf_setlen(error_message, 0);
	strbuf_addstr(error_message, curl_easy_strerror(results.curl_result));

	curl_slist_free_all(headers);

	return ret;
}

/*
 * When talking to the main Git server we can either:
 * [1] POST w/no creds, get 401, fill creds, POST w/ creds.
 * [2] proactively fill creds, POST w/ creds.
 *
 * The http.c layer doesn't have a routine that does [1] for us like it
 * does for GET.  remote-curl.c:post_rpc() is the closest equivalent
 * that I've seen.
 *
 * Since the POST is likely to send a very large payload body, I'd
 * rather we do [2] than [1] if possible and avoid the extra round-trip
 * and (potentially) large upload.
 *
 * However, if the cached creds are bogus, we may still get a 401
 * challenge.  We can then reject the creds, re-fill them, and try
 * again.
 */

static int do_post__to_main(const char *url_component,
			    const struct strbuf *post_payload,
			    struct tempfile *tempfile,
			    struct strbuf *received_content_type,
			    struct strbuf *error_message)
{
	int ret = HTTP_OK;
	const struct credential *p_creds = NULL;
	long http_response_code;

	lookup_main_creds();

	if (rv_data.main_creds.username && *rv_data.main_creds.username)
		p_creds = &rv_data.main_creds;

	strbuf_setlen(error_message, 0);
	trace2_region_enter("remote-vfs", "POST/object/main1", NULL);
	ret = do_post(rv_data.buf_main_url.buf, url_component,
		      p_creds, post_payload, tempfile, received_content_type,
		      &http_response_code, error_message);
	trace2_region_leave("remote-vfs", "POST/object/main1", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;

	if (ret != HTTP_REAUTH)
		return ret;

	refresh_main_creds();

	/*
	 * Since we are automatically retrying, truncate the error
	 * message from the first attempt.  The caller should only
	 * see the error message from the final attempt.
	 */
	strbuf_setlen(error_message, 0);

	p_creds = &rv_data.main_creds;
	trace2_region_enter("remote-vfs", "POST/object/main2", NULL);
	ret = do_post(rv_data.buf_main_url.buf, url_component,
		      p_creds, post_payload, tempfile, received_content_type,
		      &http_response_code, error_message);
	trace2_region_leave("remote-vfs", "POST/object/main2", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;
	return ret;
}

/*
 * When talking to the cache-server we must use creds obtained from the
 * main Git server.
 *
 * The cache-server DOES NOT do 401s, so we must always force creds into
 * the request.  This is like [2] above.
 */
static int do_post__to_cache_server(const char *url_component,
				    const struct strbuf *post_payload,
				    struct tempfile *tempfile,
				    struct strbuf *received_content_type,
				    struct strbuf *error_message)
{
	long http_response_code;
	int ret = HTTP_OK;

	synthesize_cache_server_creds();

	strbuf_setlen(error_message, 0);
	trace2_region_enter("remote-vfs", "POST/object/cs1", NULL);
	ret = do_post(rv_data.buf_cache_server_url.buf,
		      url_component, &rv_data.cache_creds,
		      post_payload, tempfile, received_content_type,
		      &http_response_code, error_message);
	trace2_region_leave("remote-vfs", "POST/object/cs1", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;

	if (http_response_code == 404)
		return RV_ERROR__NOT_FOUND;

	if (http_response_code != 400)
		return RV_ERROR__ERROR;

	/* Assume a 400 is a virtual-401 and retry */

	refresh_cache_server_creds();

	strbuf_setlen(error_message, 0);
	trace2_region_enter("remote-vfs", "POST/object/cs2", NULL);
	ret = do_post(rv_data.buf_cache_server_url.buf,
		      url_component, &rv_data.cache_creds,
		      post_payload, tempfile, received_content_type,
		      &http_response_code, error_message);
	trace2_region_leave("remote-vfs", "POST/object/cs2", NULL);
	if (ret == HTTP_OK)
		return HTTP_OK;
	return ret;
}

/*
 * Send a POST request to cache-server if present and fallback to the
 * main Git server if necessary.
 *
 * url_component contains something like "gvfs/objects".
 */
static int do_post__with_fallback(const char *url_component,
				  const struct strbuf *post_payload,
				  struct tempfile *tempfile,
				  struct strbuf *received_content_type,
				  struct strbuf *error_message)
{
	int ret = HTTP_OK;

	if (rv_data.buf_cache_server_url.len) {
		ret = do_post__to_cache_server(
			url_component, post_payload, tempfile,
			received_content_type, error_message);
		if (ret == HTTP_OK)
			return ret;

		if (!rv_opts.param__allow_fallback)
			return ret;
	}

	ret = do_post__to_main(url_component, post_payload, tempfile,
			       received_content_type, error_message);
	if (ret == HTTP_OK)
		return HTTP_OK;
	return ret;
}

/*
 * Send a "gvfs/objects" HTTP POST with a JSON payload containing
 * the desired OIDs.  First, try the cache-server (if present) and
 * optionally fallback to the main Git server.
 */
static int rest__post__gvfs_objects(const struct strbuf *post_payload,
				    struct tempfile *tempfile,
				    struct strbuf *received_content_type,
				    struct strbuf *error_message)
{
	int ret = HTTP_OK;

	rv_http_init();

	trace2_region_enter("remote-vfs", "POST/gvfs/objects", NULL);
	ret = do_post__with_fallback("gvfs/objects", post_payload, tempfile,
				     received_content_type, error_message);
	trace2_data_intmax("remote-vfs", NULL, "POST/result", ret);
//	if (ret == HTTP_OK)
//		trace2_data_string("remote-vfs", NULL, "POST/content-type",
//				   received_content_type->buf);
	trace2_region_leave("remote-vfs", "POST/gvfs/objects", NULL);

	rv_http_cleanup();

	return ret;
}

static void do__packfile__gvfs_objects(struct oidset *oids,
				       int depth,
				       struct strbuf *packfile_name)
{
	struct tempfile *tempfile = NULL;
	struct json_writer jw_req = JSON_WRITER_INIT;
	struct strbuf received_content_type = STRBUF_INIT;
	struct strbuf error_message = STRBUF_INIT;
	int ret = HTTP_OK;

	build_json_payload__gvfs_objects(&jw_req, depth, oids);

	tempfile = create_tempfile_for_packfile();

	ret = rest__post__gvfs_objects(&jw_req.json, tempfile,
				       &received_content_type, &error_message);
	fflush(tempfile->fp);

	jw_release(&jw_req);

	if (ret != HTTP_OK) {
		delete_tempfile(&tempfile);
		die("%s", error_message.buf);
	}

	strbuf_release(&error_message);

	if (!strcmp(received_content_type.buf,
		    "application/x-git-packfile")) {
		install_packfile(&tempfile, packfile_name);
		tempfile = NULL;
	}
	else if (!strcmp(received_content_type.buf,
			 "application/x-git-loose-object"))
	{
		/*
		 * This should not happen (when we request more than
		 * one object).  The server can send us a loose object
		 * (even when we use the POST form) if there is only
		 * one object in the payload (and despite the set of
		 * accept headers we send), so I'm going to leave this
		 * here.
		 */
		delete_tempfile(&tempfile);
		BUG("received loose object when packfile expected");
	}
	else {
		delete_tempfile(&tempfile);
		die("unknown content-type '%s'", received_content_type.buf);
	}
}

//////////////////////////////////////////////////////////////////

/*
 * Finish with initialization.  This happens after the main option
 * parsing, dispatch to sub-command, and sub-command option parsing
 * and before actually doing anything.
 *
 * Optionally configure the cache-server if the sub-command will
 * use it.
 */
static void finish_init(int setup_cache_server)
{
	lookup_odb_paths();

	choose_mode();

	lookup_main_url();

	if (setup_cache_server)
		select_cache_server();

	select_odb();
}

/*
 * Request gvfs/config from main Git server.  Print the received
 * server configuration.
 */
static int do_sub_cmd__config(int argc, const char **argv)
{
	struct strbuf config_data = STRBUF_INIT;
	int ret = HTTP_OK;

	trace2_cmd_mode("config");

	finish_init(0);

	trace2_region_enter("remote-vfs", "config", NULL);
	ret = rest__get__gvfs_config(&config_data);
	trace2_region_leave("remote-vfs", "config", NULL);
	
	if (ret != HTTP_OK) {
		// TODO print error
	}
	else
		printf("%s\n", config_data.buf);

	strbuf_release(&config_data);

	return ret;
}

/*
 * Bulk fetch a list of missing objects.  Read the list from stdin
 * assuming it comes from `rev-list` and has '?' markers.
 *
 * Create a packfile (or a loose object if only one OID requested).
 */
static int do_sub_cmd__get_missing(int argc, const char **argv)
{
	static int depth = 1;

	static struct option get_missing_options[] = {
		OPT_INTEGER('d', "depth", &depth,
			    N_("Commit depth")),
		OPT_CALLBACK(0, "cache-server", NULL,
			     N_("cache-server"),
			     N_("cache-server=disable|allow|verify|error"),
			     option_parse_csu),
		OPT_END(),
	};

	struct oidset oids = OIDSET_INIT;
	struct oidset_iter iter;
	struct strbuf output_pathname = STRBUF_INIT;
	int count;
	int ret = HTTP_OK;

	trace2_cmd_mode("get-missing");

	if (argc > 1 && !strcmp(argv[1], "-h"))
		usage_with_options(get_missing_usage, get_missing_options);

	argc = parse_options(argc, argv, NULL, get_missing_options,
			     get_missing_usage, 0);

	finish_init(1);

	count = read_stdin_from_rev_list(&oids, 1);
	trace2_data_intmax("remote-vfs", NULL, "get-missing/count", count);

	switch (count) {
	case 0:
		printf("emptyset\n");
		ret = HTTP_OK;
		break;

	case 1:
		oidset_iter_init(&oids, &iter);
		do__loose__gvfs_object(oidset_iter_next(&iter),
				       &output_pathname);
		printf("loose %s\n", output_pathname.buf);
		break;

	default:
		do__packfile__gvfs_objects(&oids, depth, &output_pathname);

		printf("packfile %d %s\n", count, output_pathname.buf);
		break;
	}

	strbuf_release(&output_pathname);
	oidset_clear(&oids);
	return ret;
}

static int do_sub_cmd(int argc, const char **argv)
{
	if (!strcmp(argv[0], "get-missing"))
		return do_sub_cmd__get_missing(argc, argv);

	if (!strcmp(argv[0], "config"))
		return do_sub_cmd__config(argc, argv);

	// TODO have "interactive" mode that behaves like
	// TODO current read-object-hook and could do a
	// TODO series of batches or individual items.
	// TODO
	// TODO have "test" mode that could be used to drive
	// TODO unit testing.

	return RV_ERROR__USAGE;
}

/*
 * Connect to primary Git server or a cache-server using the GVFS Protocol.
 * https://github.com/microsoft/VFSForGit/blob/master/Protocol.md
 */
int cmd_main(int argc, const char **argv)
{
	static struct option main_options[] = {
		OPT_STRING('r', "remote", &rv_opts.param__remote_name,
			   N_("remote"),
			   N_("Remote name")),
		OPT_CALLBACK('m', "mode", NULL,
			     N_("mode"),
			     N_("mode=auto|vfs|scalar|none"),
			     option_parse_mode),
		OPT_BOOL('f', "fallback", &rv_opts.param__allow_fallback,
			 N_("Fallback to Git server if cache-server fails")),
		OPT_END(),
	};

	int nongit;
	int ret;

	if (argc > 1 && !strcmp(argv[1], "-h"))
		usage_with_options(main_usage, main_options);

	trace2_cmd_name("remote-vfs");

	setup_git_directory_gently(&nongit);

	git_config(config_cb, NULL);

	argc = parse_options(argc, argv, NULL, main_options, main_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc == 0)
		usage_with_options(main_usage, main_options);

	ret = do_sub_cmd(argc, argv);
	if (ret == RV_ERROR__USAGE)
		usage_with_options(main_usage, main_options);

	return ret;
}

// TODO Add code to call credential-store on the main Git server
// TODO after we have successfully used them.  The call to http_get_strbuf()
// TODO does this, but need to confirm usage in my custom curl_ calls to
// TODO do GET and POST.
//
// TODO Consider replacing http_get_strbuf() with custom curl_ GET
// TODO calls so that I can manage the creds consistently with the
// TODO other calls in here.  (For example, if POST gvfs/objects to
// TODO the cache-server fails, I can use GET gvfs/config to the main
// TODO Git server to force the creds to be updated.  But some of creds
// TODO are cached in http.c and some here.
