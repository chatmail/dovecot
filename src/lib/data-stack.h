#ifndef DATA_STACK_H
#define DATA_STACK_H

/* Data stack makes it very easy to implement functions returning dynamic data
   without having to worry much about memory management like freeing the
   result or having large enough buffers for the result.

   t_ prefix was chosen to describe functions allocating memory from data
   stack. "t" meaning temporary.

   Advantages over control stack and alloca():
    - Functions can return a value allocated from data stack
    - We can portably specify how much data we want to allocate at runtime

   Advantages over malloc():
    - FAST, most of the time allocating memory means only updating a couple of
      pointers and integers. Freeing the memory all at once also is a fast
      operation.
    - No need to free() each allocation resulting in prettier code
    - No memory leaks
    - No memory fragmentation

   Disadvantages:
    - Allocating memory inside loops can accidentally allocate a lot of memory
      if the loops are long and you forgot to place t_push() and t_pop() there.
    - t_malloc()ed data could be accidentally stored into permanent location
      and accessed after it's already been freed. const'ing the return values
      helps for most uses though (see the t_malloc() description).
    - Debugging invalid memory usage may be difficult using existing tools,
      although compiling with DEBUG enabled helps finding simple buffer
      overflows.
*/

#ifndef STATIC_CHECKER
typedef unsigned int data_stack_frame_t;
#else
typedef struct data_stack_frame *data_stack_frame_t;
#endif

extern unsigned int data_stack_frame_id;

/* All t_..() allocations between t_push*() and t_pop() are freed after t_pop()
   is called. Returns the current stack frame number, which can be used
   to detect missing t_pop() calls:

   x = t_push(marker); .. if (!t_pop(x)) abort();

   In DEBUG mode, t_push_named() makes a temporary allocation for the name,
   but is safe to call in a loop as it performs the allocation within its own
   frame. However, you should always prefer to use T_BEGIN { ... } T_END below.
*/
data_stack_frame_t t_push(const char *marker) ATTR_HOT;
data_stack_frame_t t_push_named(const char *format, ...) ATTR_HOT ATTR_FORMAT(1, 2);
/* Returns TRUE on success, FALSE if t_pop() call was leaked. The caller
   should panic. */
bool t_pop(data_stack_frame_t *id) ATTR_HOT;
/* Pop the last data stack frame. This shouldn't be called outside test code. */
void t_pop_last_unsafe(void);

/* Usage: T_BEGIN { code } T_END */
#define T_STRING(x)	#x
#define T_XSTRING(x)	T_STRING(x)	/* expand and then stringify */
#define T_BEGIN \
	STMT_START { \
		data_stack_frame_t _data_stack_cur_id = t_push(__FILE__ ":" T_XSTRING(__LINE__));
#define T_END \
	STMT_START { \
		if (unlikely(!t_pop(&_data_stack_cur_id))) \
			i_panic("Leaked t_pop() call"); \
	} STMT_END; \
	} STMT_END

/* WARNING: Be careful when using these functions, it's too easy to
   accidentally save the returned value somewhere permanently.

   You probably should never use these functions directly, rather
   create functions that return 'const xxx*' types and use t_malloc()
   internally in them. This is a lot safer, since usually compiler
   warns if you try to place them in xxx*. See strfuncs.c for examples.

   t_malloc() calls never fail. If there's not enough memory left,
   i_panic() will be called. */
void *t_malloc_no0(size_t size) ATTR_MALLOC ATTR_RETURNS_NONNULL;
void *t_malloc0(size_t size) ATTR_MALLOC ATTR_RETURNS_NONNULL;

/* Try growing allocated memory. Returns TRUE if successful. Works only
   for last allocated memory in current stack frame. */
bool t_try_realloc(void *mem, size_t size);

/* Returns the number of bytes available in data stack without allocating
   more memory. */
size_t t_get_bytes_available(void) ATTR_PURE;

#define t_new(type, count) \
	((type *) t_malloc0(MALLOC_MULTIPLY((unsigned int)sizeof(type), (count))) + \
	 COMPILE_ERROR_IF_TRUE(sizeof(type) > UINT_MAX))

/* Returns pointer to a temporary buffer you can use. The buffer will be
   invalid as soon as next t_malloc() is called!

   If you wish to grow the buffer, you must give the full wanted size
   in the size parameter. If return value doesn't point to the same value
   as last time, you need to memcpy() data from the old buffer to the
   new one (or do some other trickery). See t_buffer_reget(). */
void *t_buffer_get(size_t size) ATTR_RETURNS_NONNULL;

/* Grow the buffer, memcpy()ing the memory to new location if needed. */
void *t_buffer_reget(void *buffer, size_t size) ATTR_RETURNS_NONNULL;

/* Make the last t_buffer_get()ed buffer permanent. Note that size MUST be
   less or equal than the size you gave with last t_buffer_get() or the
   result will be undefined. */
void t_buffer_alloc(size_t size);
/* Allocate the last t_buffer_get()ed data entirely. */
void t_buffer_alloc_last_full(void);

/* If enabled, all the used memory is cleared after t_pop(). */
void data_stack_set_clean_after_pop(bool enable);

/* Returns the number of bytes currently used in data stack. */
size_t data_stack_get_used_size(void);

void data_stack_init(void);
void data_stack_deinit(void);

#endif
