/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */
#include "lib.h"
#include "safe-memset.h"
#include "mempool.h"
#include "llist.h"

#define MAX_ALLOC_SIZE SSIZE_T_MAX

struct allocfree_pool {
	struct pool pool;
	int refcount;
	size_t total_alloc_count;
	size_t total_alloc_used;

	struct pool_block *blocks;
#ifdef DEBUG
	char *name;
#endif
	bool clean_frees;
};

struct pool_block {
	struct pool_block *prev,*next;

	size_t size;
	unsigned char *block;
};

#define SIZEOF_ALLOCFREE_POOL MEM_ALIGN(sizeof(struct allocfree_pool))
#define SIZEOF_POOLBLOCK (MEM_ALIGN(sizeof(struct pool_block)))

static const char *pool_allocfree_get_name(pool_t pool);
static void pool_allocfree_ref(pool_t pool);
static void pool_allocfree_unref(pool_t *pool);
static void *pool_allocfree_malloc(pool_t pool, size_t size);
static void pool_allocfree_free(pool_t pool, void *mem);
static void *pool_allocfree_realloc(pool_t pool, void *mem,
				    size_t old_size, size_t new_size);
static void pool_allocfree_clear(pool_t pool);
static size_t pool_allocfree_get_max_easy_alloc_size(pool_t pool);

static const struct pool_vfuncs static_allocfree_pool_vfuncs = {
	pool_allocfree_get_name,

	pool_allocfree_ref,
	pool_allocfree_unref,

	pool_allocfree_malloc,
	pool_allocfree_free,

	pool_allocfree_realloc,

	pool_allocfree_clear,
	pool_allocfree_get_max_easy_alloc_size
};

static const struct pool static_allocfree_pool = {
	.v = &static_allocfree_pool_vfuncs,

	.alloconly_pool = FALSE,
	.datastack_pool = FALSE
};

pool_t pool_allocfree_create(const char *name ATTR_UNUSED)
{
	struct allocfree_pool *pool;
	pool = calloc(1, SIZEOF_ALLOCFREE_POOL);
	if (pool == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "calloc(1, %"PRIuSIZE_T"): Out of memory",
			       SIZEOF_ALLOCFREE_POOL);
#ifdef DEBUG
	pool->name = strdup(name);
#endif
	pool->pool = static_allocfree_pool;
	pool->refcount = 1;
	return &pool->pool;
}

pool_t pool_allocfree_create_clean(const char *name)
{
	struct allocfree_pool *apool;
	pool_t pool;

	pool = pool_allocfree_create(name);
	apool = (struct allocfree_pool *)pool;
	apool->clean_frees = TRUE;
	return pool;
}

static void pool_allocfree_destroy(struct allocfree_pool *apool)
{
	pool_allocfree_clear(&apool->pool);
	if (apool->clean_frees)
		safe_memset(apool, 0, SIZEOF_ALLOCFREE_POOL);
#ifdef DEBUG
	free(apool->name);
#endif
	free(apool);
}

static const char *pool_allocfree_get_name(pool_t pool ATTR_UNUSED)
{
#ifdef DEBUG
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	return apool->name;
#else
	return "alloc";
#endif
}

static void pool_allocfree_ref(pool_t pool)
{
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	i_assert(apool->refcount > 0);

	apool->refcount++;
}

static void pool_allocfree_unref(pool_t *_pool)
{
	pool_t pool = *_pool;
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	i_assert(apool->refcount > 0);

	/* erase the pointer before freeing anything, as the pointer may
	   exist inside the pool's memory area */
	*_pool = NULL;

	if (--apool->refcount > 0)
		return;

	pool_allocfree_destroy(apool);
}

static void *pool_block_attach(struct allocfree_pool *apool, struct pool_block *block)
{
	i_assert(block->size > 0);
	DLLIST_PREPEND(&apool->blocks, block);
	block->block = PTR_OFFSET(block,SIZEOF_POOLBLOCK);
	apool->total_alloc_used += block->size;
	apool->total_alloc_count++;
	return block->block;
}

static struct pool_block *
pool_block_detach(struct allocfree_pool *apool, unsigned char *mem)
{
	struct pool_block *block = PTR_OFFSET(mem, -SIZEOF_POOLBLOCK);

	/* make sure the block we are dealing with is correct */
	i_assert(block->block == mem);
	i_assert((block->prev == NULL || block->prev->next == block) &&
		 (block->next == NULL || block->next->prev == block));

	i_assert(apool->total_alloc_used >= block->size);
	i_assert(apool->total_alloc_count > 0);
	DLLIST_REMOVE(&apool->blocks, block);
	apool->total_alloc_used -= block->size;
	apool->total_alloc_count--;

	return block;
}

static void *pool_allocfree_malloc(pool_t pool, size_t size)
{
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);

	if (unlikely(size == 0 || size > SSIZE_T_MAX - SIZEOF_POOLBLOCK))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	struct pool_block *block = calloc(1, SIZEOF_POOLBLOCK + size);
	if (block == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "calloc(1, %"PRIuSIZE_T"): Out of memory",
			       SIZEOF_POOLBLOCK + size);
	block->size = size;
	return pool_block_attach(apool, block);
}

static void pool_allocfree_free(pool_t pool, void *mem)
{
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	if (mem == NULL)
		return;
	struct pool_block *block = pool_block_detach(apool, mem);
	if (apool->clean_frees)
		safe_memset(block, 0, SIZEOF_POOLBLOCK+block->size);
	free(block);
}

static void *pool_allocfree_realloc(pool_t pool, void *mem,
				    size_t old_size, size_t new_size)
{
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	unsigned char *new_mem;

	if (unlikely(new_size == 0 || new_size > SSIZE_T_MAX - SIZEOF_POOLBLOCK))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", new_size);

	if (mem == NULL)
		return pool_allocfree_malloc(pool, new_size);

	struct pool_block *block = pool_block_detach(apool, mem);
	if ((new_mem = realloc(block, SIZEOF_POOLBLOCK+new_size)) == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "realloc(block, %"PRIuSIZE_T")",
			       SIZEOF_POOLBLOCK+new_size);

	/* zero out new memory */
	if (new_size > old_size)
		memset(new_mem + SIZEOF_POOLBLOCK + old_size, 0,
		       new_size - old_size);
	block = (struct pool_block*)new_mem;
	block->size = new_size;
	return pool_block_attach(apool, block);
}

static void pool_allocfree_clear(pool_t pool)
{
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	struct pool_block *block, *next;

	for (block = apool->blocks; block != NULL; block = next) {
		next = block->next;
		pool_allocfree_free(pool, block->block);
	}
	i_assert(apool->total_alloc_used == 0 && apool->total_alloc_count == 0);
}

static size_t pool_allocfree_get_max_easy_alloc_size(pool_t pool ATTR_UNUSED)
{
	return 0;
}

size_t pool_allocfree_get_total_used_size(pool_t pool)
{
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	return apool->total_alloc_used;
}

size_t pool_allocfree_get_total_alloc_size(pool_t pool)
{
	struct allocfree_pool *apool =
		container_of(pool, struct allocfree_pool, pool);
	return apool->total_alloc_used +
	       SIZEOF_POOLBLOCK*apool->total_alloc_count + sizeof(*apool);
}
