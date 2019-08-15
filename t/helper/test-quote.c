#include "test-tool.h"
#include "quote.h"
#include "strbuf.h"
#include "string.h"

int cmd__quote_buf_pretty(int argc, const char **argv)
{
	struct strbuf buf_payload = STRBUF_INIT;
	char *nullString = 0;
	char empty[5] = {'\0'};

	if (!argv[1]) {
		strbuf_release(&buf_payload);
		die("missing input string");
	}

	if (!strcmp(argv[1], "nullString")) {
		sq_quote_buf_pretty(&buf_payload, nullString);

		/*
		 * Cushion the result with '.'s 
		 * to make the test script more readable
		 */
		printf(".%s.\n", buf_payload.buf);
		strbuf_release(&buf_payload);
		return 0;
	}

	if (!strcmp(argv[1], "")) {
		sq_quote_buf_pretty(&buf_payload, empty);

		/*
		 * Cushion the result with '.'s 
		 * to make the test script more readable
		 */
		printf(".%s.\n", buf_payload.buf);
		strbuf_release(&buf_payload);
		return 0;
	}

	sq_quote_buf_pretty(&buf_payload, argv[1]);
	printf("%s\n", buf_payload.buf);

	strbuf_release(&buf_payload);
	return 0;
}
