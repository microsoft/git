#include "cache.h"
#include "tr2_tbuf.h"

void tr2_tbuf_current_time(struct tr2_tbuf *tb)
{
	struct timeval tv;
	struct tm tm;
	time_t secs;

	gettimeofday(&tv, NULL);
	secs = tv.tv_sec;
	localtime_r(&secs, &tm);

	xsnprintf(tb->buf, sizeof(tb->buf), "%02d:%02d:%02d.%06ld",
		  tm.tm_hour, tm.tm_min, tm.tm_sec, (long)tv.tv_usec);
}

