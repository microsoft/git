#ifndef FSCACHE_H
#define FSCACHE_H

/*
 * The fscache is thread specific. enable_fscache() must be called
 * for each thread where caching is desired.
 */

int fscache_enable(int enable);
#define enable_fscache(x) fscache_enable(x)

int fscache_enabled(const char *path);
#define is_fscache_enabled(path) fscache_enabled(path)

void fscache_flush(void);
#define flush_fscache() fscache_flush()

DIR *fscache_opendir(const char *dir);
int fscache_lstat(const char *file_name, struct stat *buf);

/* opaque fscache structure */
struct fscache;

struct fscache *fscache_getcache(void);
void fscache_mergecache(struct fscache *dest);

#endif
