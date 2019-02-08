#include "git-compat-util.h"
#include "version.h"

#ifndef NO_CURL
#include <curl/curl.h>
#endif

#ifndef NO_ICONV
#include <iconv.h>
#endif

#ifdef NO_CURL
static void dump_curl_info(void)
{
	printf("curl: NO_CURL\n");
}
#else
static void dump_curl_protocols(curl_version_info_data *cvid)
{
	const char * const *a = cvid->protocols;

	printf("curl:protocols:");
	while (*a)
		printf(" %s", *a++);
	printf("\n");
}

static void dump_curl_info(void)
{
	curl_version_info_data *cvid;

	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		printf("curl:init: failed\n");
		return;
	}

	cvid = curl_version_info(CURLVERSION_NOW);

	printf("curl:age: %d\n", cvid->age);

	if (cvid->age >= 0) {
		printf("curl:version: %s\n", cvid->version);
		printf("curl:version_num: 0x%08x\n", cvid->version_num);

		printf("curl:host: %s\n", cvid->host);

		printf("curl:features: 0x%08x\n", cvid->features);

		printf("curl:ssl_version: %s\n",
		       cvid->ssl_version ? cvid->ssl_version : "(null)");

		printf("curl:libz_version: %s\n",
		       cvid->libz_version ? cvid->libz_version : "(null)");

		if (cvid->protocols)
			dump_curl_protocols(cvid);
	}

	if (cvid->age >= 1) {
		/* TODO do we care about "ares" ? */
	}
	if (cvid->age >= 2) {
		/* TODO do we care about "libidn" ? */
	}

	if (cvid->age >= 3) {
		printf("curl:iconv_version: %d\n", cvid->iconv_ver_num);

		printf("curl:libssh_version: %s\n",
		       cvid->libssh_version ? cvid->libssh_version : "(null)");
	}

	/* TODO age >= 4 */
}
#endif /* CURL */

#ifdef NO_ICONV
static void dump_iconv_info(void)
{
	printf("iconv: NO_ICONV\n");
}
#else
static void dump_iconv_info(void)
{
	/* the header that we compiled against */
	printf("iconv:dot_h_version: 0x%08x\n", _LIBICONV_VERSION);

	/* the symbol exported from the DLL we linked to */
	printf("iconv:dll_version:   0x%08x\n", _libiconv_version);
}
#endif

int cmd_main(int argc, const char **argv)
{
	printf("git-version: %s\n", git_version_string);

	printf("cpu:type: %s\n", GIT_HOST_CPU);
	printf("cpu:sizeof-long: %d\n", (int)sizeof(long));
	printf("cpu:sizeof-size_t: %d\n", (int)sizeof(size_t));
	printf("cpu:sizeof-ptr: %d\n", (int)sizeof(void*));
	
	printf("commit: %s\n", 
	       git_built_from_commit_string[0] ?
	       git_built_from_commit_string : "(none)");

	dump_curl_info();

	dump_iconv_info();

	return 0;
}
