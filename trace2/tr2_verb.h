#ifndef TR2_VERB_H
#define TR2_VERB_H

/*
 * This file contains "private/protected" routines for TRACE2.
 */

/*
 * Append the current git command's "verb" to the list being maintained
 * in the environment.
 *
 * The hierarchy for a top-level git command is just the current verb.
 * For a child git process, the hierarchy lists the verbs of the parent
 * git processes (much like the SID).
 *
 * The hierarchy for the current process will be exported to the environment
 * and inherited by child processes.
 */
void tr2_verb_append_hierarchy(const char *verb);

/*
 * Get the verb hierarchy for the current process.
 */
const char *tr2_verb_get_hierarchy(void);

void tr2_verb_release(void);

#endif /* TR2_VERB_H */
