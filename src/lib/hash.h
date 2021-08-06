#ifndef HASH_H
#define HASH_H

struct hash_table;

#ifdef HAVE_TYPEOF
#  define HASH_VALUE_CAST(table) (typeof((table)._value))
#else
#  define HASH_VALUE_CAST(table)
#endif

/* Returns hash code. */
typedef unsigned int hash_callback_t(const void *p);
/* Returns 0 if the pointers are equal. */
typedef int hash_cmp_callback_t(const void *p1, const void *p2);

/* Create a new hash table. If initial_size is 0, the default value is used.
   table_pool is used to allocate/free large hash tables, node_pool is used
   for smaller allocations and can also be alloconly pool. The pools must not
   be free'd before hash_table_destroy() is called. */
void hash_table_create(struct hash_table **table_r, pool_t node_pool,
		       unsigned int initial_size,
		       hash_callback_t *hash_cb,
		       hash_cmp_callback_t *key_compare_cb);
#define hash_table_create(table, pool, size, hash_cb, key_cmp_cb) \
	TYPE_CHECKS(void, \
	COMPILE_ERROR_IF_TRUE( \
		sizeof((*table)._key) != sizeof(void *) || \
		sizeof((*table)._value) != sizeof(void *)) || \
	COMPILE_ERROR_IF_TRUE( \
               !__builtin_types_compatible_p(typeof(&key_cmp_cb), \
                       int (*)(typeof((*table)._key), typeof((*table)._key))) && \
               !__builtin_types_compatible_p(typeof(&key_cmp_cb), \
                       int (*)(typeof((*table)._const_key), typeof((*table)._const_key)))) || \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof(&hash_cb), \
			unsigned int (*)(typeof((*table)._key))) && \
		!__builtin_types_compatible_p(typeof(&hash_cb), \
		unsigned int (*)(typeof((*table)._const_key)))), \
	hash_table_create(&(*table)._table, pool, size, \
		(hash_callback_t *)hash_cb, \
		(hash_cmp_callback_t *)key_cmp_cb))

/* Create hash table where comparisons are done directly with the pointers. */
void hash_table_create_direct(struct hash_table **table_r, pool_t node_pool,
			      unsigned int initial_size);
#define hash_table_create_direct(table, pool, size) \
	TYPE_CHECKS(void, \
	COMPILE_ERROR_IF_TRUE( \
		sizeof((*table)._key) != sizeof(void *) || \
		sizeof((*table)._value) != sizeof(void *)), \
	hash_table_create_direct(&(*table)._table, pool, size))

#define hash_table_is_created(table) \
	((table)._table != NULL)

void hash_table_destroy(struct hash_table **table);
#define hash_table_destroy(table) \
	hash_table_destroy(&(*table)._table)
/* Remove all nodes from hash table. If free_collisions is TRUE, the
   memory allocated from node_pool is freed, or discarded with alloconly pools.
   WARNING: If you p_clear() the node_pool, the free_collisions must be TRUE. */
void hash_table_clear(struct hash_table *table, bool free_collisions);
#define hash_table_clear(table, free_collisions) \
	hash_table_clear((table)._table, free_collisions)

void *hash_table_lookup(const struct hash_table *table, const void *key) ATTR_PURE;
#define hash_table_lookup(table, key) \
	TYPE_CHECKS(void *, \
	COMPILE_ERROR_IF_TYPES2_NOT_COMPATIBLE((table)._key, (table)._const_key, key), \
	HASH_VALUE_CAST(table)hash_table_lookup((table)._table, (key)))

bool hash_table_lookup_full(const struct hash_table *table,
			    const void *lookup_key,
			    void **orig_key_r, void **value_r);
#ifndef __cplusplus
#  define hash_table_lookup_full(table, lookup_key, orig_key_r, value_r) \
	TYPE_CHECKS(bool, \
	COMPILE_ERROR_IF_TYPES2_NOT_COMPATIBLE((table)._const_key, (table)._key, lookup_key) || \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._keyp, orig_key_r) || \
	COMPILE_ERROR_IF_TRUE(sizeof(*(orig_key_r)) != sizeof(void *)) || \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._valuep, value_r) || \
	COMPILE_ERROR_IF_TRUE(sizeof(*(value_r)) != sizeof(void *)), \
	hash_table_lookup_full((table)._table, \
		(lookup_key), (void *)(orig_key_r), (void *)(value_r)))
#else
/* C++ requires (void **) casting, but that's not possible with strict
   aliasing, so .. we'll just disable the type checks */
#  define hash_table_lookup_full(table, lookup_key, orig_key_r, value_r) \
	hash_table_lookup_full((table)._table, lookup_key, orig_key_r, value_r)
#endif

/* Suppose to insert a new key-value node to the hash table.
   If the key already exists, assert-crash. */
void hash_table_insert(struct hash_table *table, void *key, void *value);
/* If the key doesn't exists, do the exact same as hash_table_insert()
   If the key already exists, preserve the original key and update only the value.*/
void hash_table_update(struct hash_table *table, void *key, void *value);
#define hash_table_insert(table, key, value) \
	TYPE_CHECKS(void, \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._key, key) || \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._value, value), \
	hash_table_insert((table)._table, (void *)(key), (void *)(value)))
#define hash_table_update(table, key, value) \
	TYPE_CHECKS(void, \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._key, key) || \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._value, value), \
	hash_table_update((table)._table, (void *)(key), (void *)(value)))

bool hash_table_try_remove(struct hash_table *table, const void *key);
#define hash_table_try_remove(table, key) \
	TYPE_CHECKS(bool, \
	COMPILE_ERROR_IF_TYPES2_NOT_COMPATIBLE((table)._const_key, (table)._key, key), \
	hash_table_try_remove((table)._table, (const void *)(key)))
#define hash_table_remove(table, key) \
	STMT_START { \
		if (unlikely(!hash_table_try_remove(table, key))) \
        		i_panic("key not found from hash"); \
	} STMT_END
unsigned int hash_table_count(const struct hash_table *table) ATTR_PURE;
#define hash_table_count(table) \
	hash_table_count((table)._table)

/* Iterates through all nodes in hash table. You may safely call hash_table_*()
   functions while iterating, but if you add any new nodes, they may or may
   not be called for in this iteration. */
struct hash_iterate_context *hash_table_iterate_init(struct hash_table *table);
#define hash_table_iterate_init(table) \
	hash_table_iterate_init((table)._table)
bool hash_table_iterate(struct hash_iterate_context *ctx,
			void **key_r, void **value_r);
#ifndef __cplusplus
#  define hash_table_iterate(ctx, table, key_r, value_r) \
	TYPE_CHECKS(bool, \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._keyp, key_r) || \
	COMPILE_ERROR_IF_TRUE(sizeof(*(key_r)) != sizeof(void *)) || \
	COMPILE_ERROR_IF_TRUE(sizeof(*(value_r)) != sizeof(void *)) || \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE((table)._valuep, value_r), \
	hash_table_iterate(ctx, (void *)(key_r), (void *)(value_r)))
#else
/* C++ requires (void **) casting, but that's not possible with strict
   aliasing, so .. we'll just disable the type checks */
#  define hash_table_iterate(ctx, table, key_r, value_r) \
	hash_table_iterate(ctx, key_r, value_r)
#endif

void hash_table_iterate_deinit(struct hash_iterate_context **ctx);

/* Hash table isn't resized, and removed nodes aren't removed from
   the list while hash table is freezed. Supports nesting. */
void hash_table_freeze(struct hash_table *table);
void hash_table_thaw(struct hash_table *table);
#define hash_table_freeze(table) \
	hash_table_freeze((table)._table)
#define hash_table_thaw(table) \
	hash_table_thaw((table)._table)

/* Copy all nodes from one hash table to another */
void hash_table_copy(struct hash_table *dest, struct hash_table *src);
#define hash_table_copy(table1, table2) \
	hash_table_copy((table1)._table, (table2)._table)

/* hash function for strings */
unsigned int str_hash(const char *p) ATTR_PURE;
unsigned int strcase_hash(const char *p) ATTR_PURE;

/* fast hash function which uppercases a-z. Does not work well
   with input that consists from non number/letter input, as
   it works by dropping 0x20. */
unsigned int strfastcase_hash(const char *p) ATTR_PURE;

/* a generic hash for a given memory block */
unsigned int mem_hash(const void *p, unsigned int size) ATTR_PURE;

#endif
