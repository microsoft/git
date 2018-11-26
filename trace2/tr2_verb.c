#include "cache.h"
#include "trace2/tr2_verb.h"

/*
 * This file contains "private/protected" routines for TRACE2.
 */

#define TR2_ENVVAR_PARENT_VERB "GIT_TR2_PARENT_VERB"

static struct strbuf tr2verb_hierarchy = STRBUF_INIT;

void tr2_verb_append_hierarchy(const char *verb)
{
	const char *parent_verb = getenv(TR2_ENVVAR_PARENT_VERB);

	strbuf_reset(&tr2verb_hierarchy);
	if (parent_verb && *parent_verb) {
		strbuf_addstr(&tr2verb_hierarchy, parent_verb);
		strbuf_addch(&tr2verb_hierarchy, '/');
	}
	strbuf_addstr(&tr2verb_hierarchy, verb);

	setenv(TR2_ENVVAR_PARENT_VERB, tr2verb_hierarchy.buf, 1);
}

const char *tr2_verb_get_hierarchy(void)
{
	return tr2verb_hierarchy.buf;
}

void tr2_verb_release(void)
{
	strbuf_release(&tr2verb_hierarchy);
}
