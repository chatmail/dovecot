#ifndef __XMALLOC_H
#define __XMALLOC_H

#include <stdlib.h>
#include <string.h>

#define xmalloc(n) malloc(n)
#define xrealloc(n, m) realloc(n, m)
#define xzmalloc(n) calloc(n, 1)
#define xstrdup(s) strdup(s)

/* missing headers.. */
#include <sys/types.h>
#include <netinet/in.h>
#include <regex.h>
#include <fcntl.h>

/* dovecot kludges */
#include "lib.h"

/* we don't have strlcpy, but strocpy is the same except for return value */
#define strlcpy i_strocpy

#define lcase str_lcase

#endif
