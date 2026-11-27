#ifndef VIRTUALFILESYSTEM_H
#define VIRTUALFILESYSTEM_H

/*
 * Update the CE_SKIP_WORKTREE bits based on the virtual file system.
 */
void apply_virtualfilesystem(struct index_state *istate);

/*
 * Clear the specified flags for all entries in the virtual file system
 * that match the specified select mask. Returns the number of entries
 * processed.
 */
int clear_ce_flags_virtualfilesystem(struct index_state *istate, int select_mask, int clear_mask);

/*
 * Return 1 if the requested item is found in the virtual file system,
 * 0 for not found and -1 for undecided.
 */
int is_included_in_virtualfilesystem(const char *pathname, int pathlen);

/*
 * Return 1 for exclude, 0 for include and -1 for undecided.
 */
int is_excluded_from_virtualfilesystem(const char *pathname, int pathlen, int dtype);

/*
 * With a virtual file system, return 1 if the configuration turns on a
 * sparse index: cone-mode sparse-checkout and index.sparse set to true.
 * The default value of index.sparse does not count. This reads only the
 * configuration, not the sparse-checkout patterns.
 */
int vfs_sparse_index_configured(void);

/*
 * With a virtual file system, return 1 if the cone-mode sparse-checkout
 * patterns of 'istate' decide which paths are in the sparse-checkout,
 * so that the index can collapse into a sparse index. This requires
 * vfs_sparse_index_configured() and a cone-mode pattern file. It loads
 * the patterns into 'istate'.
 */
int vfs_uses_cone_patterns(struct index_state *istate);

/*
 * Free the virtual file system data structures.
 */
void free_virtualfilesystem(void);

#endif
