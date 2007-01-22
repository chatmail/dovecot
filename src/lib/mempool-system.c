/* Copyright (c) 2002-2003 Timo Sirainen */

/* @UNSAFE: whole file */

#include "lib.h"
#include "mempool.h"

#include <stdlib.h>

#ifdef HAVE_GC_GC_H
#  include <gc/gc.h>
#elif defined (HAVE_GC_H)
#  include <gc.h>
#endif

static const char *pool_system_get_name(pool_t pool);
static void pool_system_ref(pool_t pool);
static void pool_system_unref(pool_t *pool);
static void *pool_system_malloc(pool_t pool, size_t size);
static void pool_system_free(pool_t pool, void *mem);
static void *pool_system_realloc(pool_t pool, void *mem,
				 size_t old_size, size_t new_size);
static void pool_system_clear(pool_t pool);
static size_t pool_system_get_max_easy_alloc_size(pool_t pool);

static struct pool_vfuncs static_system_pool_vfuncs = {
	pool_system_get_name,

	pool_system_ref,
	pool_system_unref,

	pool_system_malloc,
	pool_system_free,

	pool_system_realloc,

	pool_system_clear,
	pool_system_get_max_easy_alloc_size
};

static struct pool static_system_pool = {
	MEMBER(v) &static_system_pool_vfuncs,

	MEMBER(alloconly_pool) FALSE,
	MEMBER(datastack_pool) FALSE
};


pool_t system_pool = &static_system_pool;

static const char *pool_system_get_name(pool_t pool __attr_unused__)
{
	return "system";
}

static void pool_system_ref(pool_t pool __attr_unused__)
{
}

static void pool_system_unref(pool_t *pool __attr_unused__)
{
}

static void *pool_system_malloc(pool_t pool __attr_unused__, size_t size)
{
	void *mem;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

#ifndef USE_GC
	mem = calloc(size, 1);
#else
	mem = GC_malloc(size);
#endif
	if (mem == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			       "pool_system_malloc(): Out of memory");
	}
	return mem;
}

static void pool_system_free(pool_t pool __attr_unused__,
			     void *mem __attr_unused__)
{
#ifndef USE_GC
	if (mem != NULL)
		free(mem);
#endif
}

static void *pool_system_realloc(pool_t pool __attr_unused__, void *mem,
				 size_t old_size, size_t new_size)
{
	if (new_size == 0 || new_size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", new_size);

#ifndef USE_GC
	mem = realloc(mem, new_size);
#else
	mem = GC_realloc(mem, new_size);
#endif
	if (mem == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			       "pool_system_realloc(): Out of memory");
	}

	if (old_size < new_size) {
                /* clear new data */
		memset((char *) mem + old_size, 0, new_size - old_size);
	}

        return mem;
}

static void pool_system_clear(pool_t pool __attr_unused__)
{
	i_panic("pool_system_clear() must not be called");
}

static size_t pool_system_get_max_easy_alloc_size(pool_t pool __attr_unused__)
{
	return 0;
}
