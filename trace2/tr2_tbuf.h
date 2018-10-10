#ifndef TR2_TBUF_H
#define TR2_TBUF_H

/*
 * This file contains "private/protected" declarations for TRACE2.
 */

/*
 * A simple wrapper around a fixed buffer to avoid C syntax
 * quirks and the need to pass around an additional size_t
 * argument.
 */
struct tr2_tbuf {
	char buf[24];
};

void tr2_tbuf_current_time(struct tr2_tbuf *tb);

#endif /* TR2_TBUF_H */
