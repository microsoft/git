#ifndef SPARSE_INDEX_H__
#define SPARSE_INDEX_H__

#include "strbuf.h"

/*
 * If performing an operation where the index is supposed to expand to a
 * full index, then disable the advice message by setting this global to
 * zero.
 */
extern int give_advice_on_expansion;

struct index_state;
struct cache_entry;
struct object_id;
#define SPARSE_INDEX_MEMORY_ONLY (1 << 0)
int is_sparse_index_allowed(struct index_state *istate, int flags);
int convert_to_sparse(struct index_state *istate, int flags);
void ensure_correct_sparsity(struct index_state *istate);
void clear_skip_worktree_from_present_files(struct index_state *istate);

/*
 * Some places in the codebase expect to search for a specific path.
 * This path might be outside of the sparse-checkout definition, in
 * which case a sparse-index may not contain a path for that index.
 *
 * Given an index and a path, check to see if a leading directory for
 * 'path' exists in the index as a sparse directory. In that case,
 * expand that sparse directory to a full range of cache entries and
 * populate the index accordingly.
 */
void expand_to_path(struct index_state *istate,
		    const char *path, size_t pathlen, int icase);

/*
 * Under core.virtualFileSystem, the working tree can contain paths inside
 * directories that a sparse index collapses into sparse-directory entries.
 * A lookup of such a path with index_name_pos() expands the whole index.
 *
 * If core.virtualFileSystem is set, the index is sparse, and a
 * sparse-directory entry contains 'path', return that entry. Otherwise
 * return NULL. If 'icase' is set, the name of the sparse-directory entry
 * can differ in case from the start of 'path'. This function never expands
 * the index. If core.virtualFileSystem is set and this function returns
 * NULL, then index_name_pos() for 'path' does not expand the index either.
 */
struct cache_entry *vfs_sparse_dir_containing(struct index_state *istate,
					      const char *path, int pathlen,
					      int icase);

/*
 * Find the part of 'path' below the sparse-directory entry 'sparse_dir'
 * in the tree of that entry. 'sparse_dir' must contain 'path'. If 'icase'
 * is set, compare names without case. Return 0 and set 'oid' and 'mode'
 * if the tree contains the path. Return -1 if it does not. Die if a tree
 * cannot be read.
 */
int sparse_dir_get_tree_entry(struct index_state *istate,
			      const struct cache_entry *sparse_dir,
			      const char *path, int pathlen, int icase,
			      struct object_id *oid, unsigned short *mode);

struct repository;
int set_sparse_index_config(struct repository *repo, int enable);

struct pattern_list;

/**
 * Scan the given index and compare its entries to the given pattern list.
 * If the index is sparse and the pattern list uses cone mode patterns,
 * then modify the index to contain the all of the file entries within that
 * new pattern list. This expands sparse directories only as far as needed.
 *
 * If the pattern list is NULL or does not use cone mode patterns, then the
 * index is expanded to a full index.
 */
void expand_index(struct index_state *istate, struct pattern_list *pl);

void ensure_full_index(struct index_state *istate);

/**
 * If there is a clear reason why the sparse index is being expanded, then
 * trace the information for why the expansion is occurring.
 */
void ensure_full_index_with_reason(struct index_state *istate,
				   const char *fmt,
				   ...);

#define ensure_full_index_unaudited(i) \
	ensure_full_index_with_reason((i), \
		"unaudited call (%s.%d)", __FILE__, __LINE__);

#endif
