/* Copyright (c) 2002-2009 Dovecot Sieve authors, see the included COPYING file
 */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "mempool.h"
#include "buffer.h"
#include "hash.h"
#include "array.h"
#include "ostream.h"

#include "sieve-error.h"
#include "sieve-extensions.h"
#include "sieve-code.h"
#include "sieve-script.h"

#include "sieve-binary.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * Config
 */
 
#define SIEVE_BINARY_VERSION_MAJOR     0
#define SIEVE_BINARY_VERSION_MINOR     1

/*
 * Macros
 */

#define SIEVE_BINARY_MAGIC              0xcafebabe
#define SIEVE_BINARY_MAGIC_OTHER_ENDIAN 0xbebafeca 

#define SIEVE_BINARY_ALIGN(offset) \
	(((offset) + 3) & ~3)
#define SIEVE_BINARY_ALIGN_PTR(ptr) \
	((void *) SIEVE_BINARY_ALIGN(((size_t) ptr)))

/* 
 * Forward declarations 
 */

struct sieve_binary_file;

static bool sieve_binary_file_open
	(struct sieve_binary_file *file, const char *path);
static void sieve_binary_file_close(struct sieve_binary_file **file);

static struct sieve_binary_block *sieve_binary_load_block
	(struct sieve_binary *sbin, unsigned int id);

static inline struct sieve_binary_extension_reg *sieve_binary_extension_get_reg
	(struct sieve_binary *sbin, const struct sieve_extension *ext, 
		bool create);
static inline int sieve_binary_extension_register
	(struct sieve_binary *sbin, const struct sieve_extension *ext, 
		struct sieve_binary_extension_reg **reg);

static inline sieve_size_t sieve_binary_emit_dynamic_data
	(struct sieve_binary *binary, const void *data, size_t size);

/* 
 * Internal structures
 */

/* Extension registration */

struct sieve_binary_extension_reg {
	/* The identifier of the extension within this binary */
	int index;
	
	/* Global extension object */
	const struct sieve_extension *extension; 
	
	/* Extension to the binary; typically used to manage extension-specific blocks 
	 * in the binary and as a means to get a binary_free notification to release
	 * references held by extensions. 
	 */
	const struct sieve_binary_extension *binext;	
	
	/* Context data associated to the binary by this extension */
	void *context;
	
	/* Main block for this extension */
	unsigned int block_id;
};

/* Block */

struct sieve_binary_block {
	buffer_t *buffer;
	int ext_index;
	
	uoff_t offset;
};

/* File */

/* FIXME: In essence this is an unbuffered stream implementation. Maybe this 
 * can be merged with the generic dovecot istream interface.
 */
struct sieve_binary_file {
	pool_t pool;
	const char *path;
	
	struct stat st;
	int fd;
	off_t offset;

	bool (*load)(struct sieve_binary_file *file);	
	const void *(*load_data)
		(struct sieve_binary_file *file, off_t *offset, size_t size);
	buffer_t *(*load_buffer)
		(struct sieve_binary_file *file, off_t *offset, size_t size);
};

/*
 * Binary object
 */

struct sieve_binary {
	pool_t pool;
	int refcount;
	
	struct sieve_script *script;
	
	struct sieve_binary_file *file;
	
	/* When the binary is loaded into memory or when it is being constructed by
	 * the generator, extensions can be associated to the binary. The extensions
	 * array is a sequential list of all linked extensions. The extension_index 
	 * array is a mapping ext_id -> binary_extension. This is used to obtain the 
	 * index code associated with an extension for this particular binary. The 
	 * linked_extensions list all extensions linked to this binary object other
	 * than the preloaded language features implemented as 'extensions'. 
	 * 
	 * All arrays refer to the same extension registration objects. Upon loading 
	 * a binary, the 'require'd extensions will sometimes need to associate 
	 * context data to the binary object in memory. This is stored in these 
	 * registration objects as well.
	 */
	ARRAY_DEFINE(extensions, struct sieve_binary_extension_reg *); 
	ARRAY_DEFINE(extension_index, struct sieve_binary_extension_reg *); 
	ARRAY_DEFINE(linked_extensions, struct sieve_binary_extension_reg *); 
		
	/* Attributes of a loaded binary */
	const char *path;
		
	/* Blocks */
	ARRAY_DEFINE(blocks, struct sieve_binary_block *); 
	unsigned int active_block;
	
	/* Current block buffer: all emit and read functions act upon this buffer */
	buffer_t *data;
	const char *code;
	size_t code_size;
};

static struct sieve_binary *sieve_binary_create(struct sieve_script *script) 
{
	pool_t pool;
	struct sieve_binary *sbin;
	unsigned int i;
	
	pool = pool_alloconly_create("sieve_binary", 8192);	
	sbin = p_new(pool, struct sieve_binary, 1);
	sbin->pool = pool;
	sbin->refcount = 1;
	sbin->script = script;
	if ( script != NULL ) 
		sieve_script_ref(script);
	
	p_array_init(&sbin->linked_extensions, pool, 5);
	p_array_init(&sbin->extensions, pool, 5);
	p_array_init(&sbin->extension_index, pool, sieve_extensions_get_count());
	
	p_array_init(&sbin->blocks, pool, 3);

	/* Pre-load core language features implemented as 'extensions' */
	for ( i = 0; i < sieve_preloaded_extensions_count; i++ ) {
		const struct sieve_extension *ext = sieve_preloaded_extensions[i];
		if ( ext->binary_load != NULL )
			(void)ext->binary_load(sbin);		
	}
			
	return sbin;
}

struct sieve_binary *sieve_binary_create_new(struct sieve_script *script) 
{
	struct sieve_binary *sbin = sieve_binary_create(script); 
	
	/* Extensions block */
	(void) sieve_binary_block_create(sbin);
	
	/* Main program block */
	(void) sieve_binary_block_set_active
		(sbin, sieve_binary_block_create(sbin), NULL);
	
	return sbin;
}

void sieve_binary_ref(struct sieve_binary *sbin) 
{
	sbin->refcount++;
}

static inline void sieve_binary_extensions_free(struct sieve_binary *sbin) 
{
	unsigned int ext_count, i;
	
	/* Cleanup binary extensions */
	ext_count = array_count(&sbin->extensions);	
	for ( i = 0; i < ext_count; i++ ) {
		struct sieve_binary_extension_reg * const *ereg
			= array_idx(&sbin->extensions, i);
		const struct sieve_binary_extension *binext = (*ereg)->binext;
		
		if ( binext != NULL && binext->binary_free != NULL )
			binext->binary_free(sbin);
	}
}

void sieve_binary_unref(struct sieve_binary **sbin) 
{
	i_assert((*sbin)->refcount > 0);

	if (--(*sbin)->refcount != 0)
		return;

	sieve_binary_extensions_free(*sbin);
	
	if ( (*sbin)->file != NULL )
		sieve_binary_file_close(&(*sbin)->file);

	if ( (*sbin)->script != NULL )
		sieve_script_unref(&(*sbin)->script);
	
	pool_unref(&((*sbin)->pool));
	
	*sbin = NULL;
}

static inline sieve_size_t _sieve_binary_get_code_size
(struct sieve_binary *sbin)
{
	return buffer_get_used_size(sbin->data);
}

sieve_size_t sieve_binary_get_code_size(struct sieve_binary *sbin)
{
	return _sieve_binary_get_code_size(sbin);
}

pool_t sieve_binary_pool(struct sieve_binary *sbin)
{
	return sbin->pool;
}

struct sieve_script *sieve_binary_script(struct sieve_binary *sbin)
{
	return sbin->script;
}

const char *sieve_binary_path(struct sieve_binary *sbin)
{
	return sbin->path;
}

bool sieve_binary_script_older
(struct sieve_binary *sbin, struct sieve_script *script)
{
	i_assert(sbin->file != NULL);
	return ( sieve_script_older(script, sbin->file->st.st_mtime) );
}

const char *sieve_binary_script_name(struct sieve_binary *sbin)
{
	struct sieve_script *script = sieve_binary_script(sbin);

	return ( script == NULL ? NULL : sieve_script_name(script) );
}

const char *sieve_binary_script_path(struct sieve_binary *sbin)
{
	struct sieve_script *script = sieve_binary_script(sbin);

	return ( script == NULL ? NULL : sieve_script_path(script) );
}


/* 
 * Block management 
 */

static inline struct sieve_binary_block *sieve_binary_block_get
(struct sieve_binary *sbin, unsigned int id) 
{
	struct sieve_binary_block * const *block;

	if  ( id >= array_count(&sbin->blocks) )
		return NULL;
	
	block = array_idx(&sbin->blocks, id);		

	return *block;
}

static inline unsigned int sieve_binary_block_add
(struct sieve_binary *sbin, struct sieve_binary_block *block)
{
	unsigned int id = array_count(&sbin->blocks);
	
	array_append(&sbin->blocks, &block, 1);	
	return id;
}

static inline unsigned int sieve_binary_block_count
(struct sieve_binary *sbin)
{
	return array_count(&sbin->blocks);
}

void sieve_binary_block_clear
(struct sieve_binary *sbin, unsigned int id)
{
	struct sieve_binary_block *block = sieve_binary_block_get(sbin, id);
	
	buffer_reset(block->buffer);
}

bool sieve_binary_block_set_active
(struct sieve_binary *sbin, unsigned int id, unsigned *old_id_r)
{
	struct sieve_binary_block *block = sieve_binary_block_get(sbin, id);
			
	if ( block == NULL ) return FALSE;
	
	if ( block->buffer == NULL ) {
		if ( sbin->file ) {
			/* Try to acces the block in the binary on disk (apperently we were lazy)
			 */
			if ( sieve_binary_load_block(sbin, id) == NULL || block->buffer == NULL )
				return FALSE;
		} else {
			/* Block buffer is missing during code generation. This is what we would 
			 * call a bug. FAIL. 
			 */
			return FALSE;
		}
	}
	
	if ( old_id_r != NULL ) 
		*old_id_r = sbin->active_block;

	sbin->data = block->buffer;
	sbin->code = buffer_get_data(block->buffer, &sbin->code_size);
	sbin->active_block = id;
	
	return TRUE;
}

unsigned int sieve_binary_block_create(struct sieve_binary *sbin)
{
	struct sieve_binary_block *block;
	
	block = p_new(sbin->pool, struct sieve_binary_block, 1);
	block->buffer = buffer_create_dynamic(sbin->pool, 64);

	return sieve_binary_block_add(sbin, block);
}

static struct sieve_binary_block *sieve_binary_block_create_id
(struct sieve_binary *sbin, unsigned int id)
{
	struct sieve_binary_block *block;
	
	block = p_new(sbin->pool, struct sieve_binary_block, 1);

	if ( id >= SBIN_SYSBLOCK_LAST )
		array_idx_set(&sbin->blocks, id, &block);		
	else
		(void)sieve_binary_block_add(sbin, block);
	
	return block;
}

/*
 * Header and record structures of the binary on disk 
 */
 
struct sieve_binary_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	uint32_t blocks;
};

struct sieve_binary_block_index {
	uint32_t id;
	uint32_t size;
	uint32_t offset;
	uint32_t ext_id;
};

struct sieve_binary_block_header {
	uint32_t id; 
	uint32_t size;
};

/* 
 * Saving the binary to a file. 
 */

static inline bool _save_skip(struct ostream *stream, size_t size)
{	
	if ( (o_stream_seek(stream, stream->offset + size)) <= 0 ) 
		return FALSE;
		
	return TRUE;
}

static inline bool _save_skip_aligned
(struct ostream *stream, size_t size, uoff_t *offset)
{
	uoff_t aligned_offset = SIEVE_BINARY_ALIGN(stream->offset);
	
	if ( (o_stream_seek(stream, aligned_offset + size)) <= 0 ) 
		return FALSE;
		
	if ( offset != NULL )
		*offset = aligned_offset;
		
	return TRUE;
}

/* FIXME: Is this even necessary for a file? */
static bool _save_full(struct ostream *stream, const void *data, size_t size)
{
	size_t bytes_left = size;
	const void *pdata = data;
	
	while ( bytes_left > 0 ) {
		ssize_t ret;
		
		if ( (ret=o_stream_send(stream, pdata, bytes_left)) <= 0 ) 
			return FALSE;
			
		pdata = PTR_OFFSET(pdata, ret);
		bytes_left -= ret;
	}	
	
	return TRUE;
}

static bool _save_aligned
(struct ostream *stream, const void *data, size_t size, uoff_t *offset)
{	
	uoff_t aligned_offset = SIEVE_BINARY_ALIGN(stream->offset);

	o_stream_cork(stream);
	
	/* Align the data by adding zeroes to the output stream */
	if ( stream->offset < aligned_offset ) {
		if ( !_save_skip(stream, aligned_offset - stream->offset) ) 
			return FALSE;
	}
	
	if ( !_save_full(stream, data, size) )
		return FALSE;
	
	o_stream_uncork(stream); 

	if ( offset != NULL )
		*offset = aligned_offset;

	return TRUE;
} 

static bool _save_block
(struct sieve_binary *sbin, struct ostream *stream, unsigned int id)
{
	struct sieve_binary_block_header block_header;
	struct sieve_binary_block *block;
	const void *data;
	size_t size;
		
	block = sieve_binary_block_get(sbin, id);
	if ( block == NULL )
		return FALSE;
		
	data = buffer_get_data(block->buffer, &size);
	
	block_header.id = id;
	block_header.size = size;
	
	if ( !_save_aligned(stream, &block_header,
		sizeof(block_header), &block->offset) )
		return FALSE;
	
	return _save_aligned(stream, data, size, NULL);
}

static bool _save_block_index_record
(struct sieve_binary *sbin, struct ostream *stream, unsigned int id)
{
	struct sieve_binary_block *block;
	struct sieve_binary_block_index header;
	
	block = sieve_binary_block_get(sbin, id);
	if ( block == NULL )
		return FALSE;
	
	header.id = id;
	header.size = buffer_get_used_size(block->buffer);
	header.ext_id = block->ext_index;
	header.offset = block->offset;
	
	if ( !_save_full(stream, &header, sizeof(header)) ) {
		sieve_sys_error("failed to save block index header %d: %m", id);
		
		return FALSE;
	}
	
	return TRUE;
}

static bool _sieve_binary_save
(struct sieve_binary *sbin, struct ostream *stream)
{
	struct sieve_binary_header header;
	unsigned int ext_count, blk_count, i;
	uoff_t block_index;
	
	blk_count = sieve_binary_block_count(sbin);
	
	/* Signal all extensions to finish generating their blocks */
	
	ext_count = array_count(&sbin->extensions);	
	for ( i = 0; i < ext_count; i++ ) {
		struct sieve_binary_extension_reg * const *ereg
			= array_idx(&sbin->extensions, i);
		const struct sieve_binary_extension *binext = (*ereg)->binext;
		
		if ( binext != NULL && binext->binary_save != NULL )
			binext->binary_save(sbin);
	}
		
	/* Create header */
	
	header.magic = SIEVE_BINARY_MAGIC;
	header.version_major = SIEVE_BINARY_VERSION_MAJOR;
	header.version_minor = SIEVE_BINARY_VERSION_MINOR;
	header.blocks = blk_count;

	if ( !_save_aligned(stream, &header, sizeof(header), NULL) ) {
		sieve_sys_error("failed to save binary header: %m");
		return FALSE;
	} 
	
	/* Skip block index for now */
	
	if ( !_save_skip_aligned(stream, 
		sizeof(struct sieve_binary_block_index) * blk_count, &block_index) )
		return FALSE;
	
	/* Create block containing all used extensions 
	 *   FIXME: Per-extension this should also store binary version numbers.
	 */
	if ( !sieve_binary_block_set_active(sbin, SBIN_SYSBLOCK_EXTENSIONS, NULL) )
		return FALSE;
		
	ext_count = array_count(&sbin->linked_extensions);
	sieve_binary_emit_unsigned(sbin, ext_count);
	
	for ( i = 0; i < ext_count; i++ ) {
		struct sieve_binary_extension_reg * const *ext
			= array_idx(&sbin->linked_extensions, i);
		
		sieve_binary_emit_cstring(sbin, (*ext)->extension->name);
		sieve_binary_emit_unsigned(sbin, (*ext)->block_id);
	}
	
	if ( !sieve_binary_block_set_active(sbin, SBIN_SYSBLOCK_MAIN_PROGRAM, NULL) )
		return FALSE;
	
	/* Save all blocks into the binary */
	
	for ( i = 0; i < blk_count; i++ ) {
		if ( !_save_block(sbin, stream, i) ) 
			return FALSE;
	}
	
	/* Create the block index */
	o_stream_seek(stream, block_index);
	for ( i = 0; i < blk_count; i++ ) {
		if ( !_save_block_index_record(sbin, stream, i) ) 
			return FALSE;
	}

	return TRUE;
} 

bool sieve_binary_save
(struct sieve_binary *sbin, const char *path)
{
	bool result = TRUE;
	const char *temp_path;
	struct ostream *stream;
	int fd;
	mode_t save_mode = sbin->script == NULL ? 0600 : sieve_script_permissions(sbin->script);
	
	/* Use default path if none is specified */
	if ( path == NULL ) {
		if ( sbin->script == NULL ) {
			sieve_sys_error("cannot determine default binary save path "
				"with missing script object");
        	return FALSE;
		}
		path = sieve_script_binpath(sbin->script);
	}

	/* Open it as temp file first, as not to overwrite an existing just yet */
	temp_path = t_strconcat(path, ".tmp", NULL);
	fd = open(temp_path, O_CREAT | O_TRUNC | O_WRONLY, save_mode);
	if ( fd < 0 ) {
		sieve_sys_error("open(%s) failed for binary save: %m", temp_path);
		return FALSE;
	}

	stream = o_stream_create_fd(fd, 0, FALSE);
	result = _sieve_binary_save(sbin, stream);
	o_stream_destroy(&stream);
 
	if (close(fd) < 0)
		sieve_sys_error("close(fd) failed for binary save: %m");

	/* Replace any original binary atomically */
	if (result && (rename(temp_path, path) < 0)) {
		sieve_sys_error("rename(%s, %s) failed for binary save: %m",
			temp_path, path);
		result = FALSE;
	}

	if ( !result ) {
		/* Get rid of temp output (if any) */
		(void) unlink(temp_path);
	} else {
		if ( sbin->path == NULL || strcmp(sbin->path, path) != 0 ) {
			sbin->path = p_strdup(sbin->pool, path);
		}
	}
	
	return result;
}

/* 
 * Binary file management 
 */

static bool sieve_binary_file_open
	(struct sieve_binary_file *file, const char *path)
{
	int fd;
	struct stat st;
	
	if ( (fd=open(path, O_RDONLY)) < 0 ) {
		if ( errno != ENOENT ) {
			sieve_sys_error("binary open(%s) failed: %m", path);
		}
		return FALSE;
	}

	if ( fstat(fd, &st) < 0 ) {
		if ( errno != ENOENT ) {
			sieve_sys_error("binary stat(%s) failed: %m", path);
		}
		return FALSE;
	}

	if ( !S_ISREG(st.st_mode) ) {
		sieve_sys_error("binary %s is not a regular file", path);
		return FALSE;		
	}
	
	file->fd = fd;
	file->st = st;

	return TRUE;
}
	
static void sieve_binary_file_close(struct sieve_binary_file **file)
{
	if ( (*file)->fd != -1 ) {
		if ( close((*file)->fd) < 0 ) {
			sieve_sys_error("binary close(fd) failed: %m");
		}
	}

	pool_unref(&(*file)->pool);
	
	*file = NULL;
}

#if 0 /* file_memory is currently unused */

/* File loaded/mapped to memory */

struct _file_memory {
	struct sieve_binary_file binfile;

	/* Pointer to the binary in memory */
	const void *memory;
	off_t memory_size;
};

static const void *_file_memory_load_data
	(struct sieve_binary_file *file, off_t *offset, size_t size)
{	
	struct _file_memory *fmem = (struct _file_memory *) file;

	*offset = SIEVE_BINARY_ALIGN(*offset);

	if ( (*offset) + size <= fmem->memory_size ) {
		const void *data = PTR_OFFSET(fmem->memory, *offset);
		*offset += size;
		file->offset = *offset;
		
		return data;
	}
		
	return NULL;
}

static buffer_t *_file_memory_load_buffer
	(struct sieve_binary_file *file, off_t *offset, size_t size)
{	
	struct _file_memory *fmem = (struct _file_memory *) file;

	*offset = SIEVE_BINARY_ALIGN(*offset);

	if ( (*offset) + size <= fmem->memory_size ) {
		const void *data = PTR_OFFSET(fmem->memory, *offset);
		*offset += size;
		file->offset = *offset;
		
		return buffer_create_const_data(file->pool, data, size);
	}
	
	return NULL;
}

static bool _file_memory_load(struct sieve_binary_file *file)
{
	struct _file_memory *fmem = (struct _file_memory *) file;
	int ret;
	size_t size;
	void *indata;
		
	i_assert(file->fd > 0);
		
	/* Allocate memory buffer
	 */
	indata = p_malloc(file->pool, file->st.st_size);
	size = file->st.st_size; 
	
	file->offset = 0; 
	fmem->memory = indata;
	fmem->memory_size = file->st.st_size;

	/* Return to beginning of the file */
	if ( lseek(file->fd, 0, SEEK_SET) == (off_t) -1 ) {
		sieve_sys_error("failed to seek() in binary %s: %m", file->path);
		return FALSE;
	}	

	/* Read the whole file into memory */
	while (size > 0) {
		if ( (ret=read(file->fd, indata, size)) <= 0 ) {
			sieve_sys_error("failed to read from binary %s: %m", file->path);
			break;
		}
		
		indata = PTR_OFFSET(indata, ret);
		size -= ret;
	}	

	if ( size != 0 ) {
		/* Failed to read the whole file */
		return FALSE;
	}
	
	return TRUE;
}

static struct sieve_binary_file *_file_memory_open(const char *path)
{
	pool_t pool;
	struct _file_memory *file;
	
	pool = pool_alloconly_create("sieve_binary_file_memory", 1024);
	file = p_new(pool, struct _file_memory, 1);
	file->binfile.pool = pool;
	file->binfile.path = p_strdup(pool, path);
	file->binfile.load = _file_memory_load;
	file->binfile.load_data = _file_memory_load_data;
	file->binfile.load_buffer = _file_memory_load_buffer;
	
	if ( !sieve_binary_file_open(&file->binfile, path) ) {
		pool_unref(&pool);
		return NULL;
	}

	return &file->binfile;
}

#endif /* file_memory is currently unused */

/* File open in lazy mode (only read what is needed into memory) */

static bool _file_lazy_read
(struct sieve_binary_file *file, off_t *offset, void *buffer, size_t size)
{
	int ret;
	void *indata = buffer;
	size_t insize = size;
	
	*offset = SIEVE_BINARY_ALIGN(*offset);
	
	/* Seek to the correct position */ 
	if ( *offset != file->offset && 
		lseek(file->fd, *offset, SEEK_SET) == (off_t) -1 ) {
		sieve_sys_error("failed to seek(fd, %lld, SEEK_SET) in binary %s: %m", 
			(long long) *offset, file->path);
		return FALSE;
	}	

	/* Read record into memory */
	while (insize > 0) {
		if ( (ret=read(file->fd, indata, insize)) <= 0 ) {
			if ( ret == 0 ) 
				sieve_sys_error("binary %s is truncated (more data expected)", 
					file->path);
			else
				sieve_sys_error("failed to read from binary %s: %m", file->path);
			break;
		}
		
		indata = PTR_OFFSET(indata, ret);
		insize -= ret;
	}	

	if ( insize != 0 ) {
		/* Failed to read the whole requested record */
		return FALSE;
	}
	
	*offset += size;
	file->offset = *offset;

	return TRUE;
}

static const void *_file_lazy_load_data
(struct sieve_binary_file *file, off_t *offset, size_t size)
{	
	void *data = t_malloc(size);

	if ( _file_lazy_read(file, offset, data, size) ) {
		return data;
	}
	
	return NULL;
}

static buffer_t *_file_lazy_load_buffer
(struct sieve_binary_file *file, off_t *offset, size_t size)
{			
	buffer_t *buffer = buffer_create_static_hard(file->pool, size);
	
	if ( _file_lazy_read
		(file, offset, buffer_get_space_unsafe(buffer, 0, size), size) ) {
		return buffer;
	}
	
	return NULL;
}

static struct sieve_binary_file *_file_lazy_open(const char *path)
{
	pool_t pool;
	struct sieve_binary_file *file;
	
	pool = pool_alloconly_create("sieve_binary_file_lazy", 4096);
	file = p_new(pool, struct sieve_binary_file, 1);
	file->pool = pool;
	file->path = p_strdup(pool, path);
	file->load_data = _file_lazy_load_data;
	file->load_buffer = _file_lazy_load_buffer;
	
	if ( !sieve_binary_file_open(file, path) ) {
		pool_unref(&pool);
		return NULL;
	}

	return file;
}

/* 
 * Load binary from a file
 */

#define LOAD_HEADER(sbin, offset, header) \
	(header *) sbin->file->load_data(sbin->file, offset, sizeof(header))

static struct sieve_binary_block *_load_block
(struct sieve_binary *sbin, off_t *offset, unsigned int id)
{
	const struct sieve_binary_block_header *header = 
		LOAD_HEADER(sbin, offset, const struct sieve_binary_block_header);
	struct sieve_binary_block *block;
		
	if ( header == NULL ) {
		sieve_sys_error("block %d of loaded binary %s is truncated", id, sbin->path);
		return NULL;
	}
	
	if ( header->id != id ) {
		sieve_sys_error("block %d of loaded binary %s has unexpected id %d", id, 
			sbin->path, header->id);
		return NULL;
	}
	
	block = sieve_binary_block_get(sbin, id);
	
	if ( block == NULL ) {
		sieve_sys_error("!!BUG!!: block %d missing in index (impossible) "
			"of binary %s",	id, sbin->path);
		return NULL;
	}
	
	block->buffer = sbin->file->load_buffer(sbin->file, offset, header->size);
	if ( block->buffer == NULL ) {
		sieve_sys_error("block %d of loaded binary %s has invalid size %d",
			id, sbin->path, header->size);
		return NULL;
	}
		
	return block;
}

static struct sieve_binary_block *sieve_binary_load_block
(struct sieve_binary *sbin, unsigned int id)
{
	struct sieve_binary_block *block;
	off_t offset;
	
	block = sieve_binary_block_get(sbin, id);
	
	if ( block == NULL ) return NULL;
	
	offset = block->offset;
	
	return _load_block(sbin, &offset, id);
}

static bool _load_block_index_record
(struct sieve_binary *sbin, off_t *offset, unsigned int id)
{
	const struct sieve_binary_block_index *record = 
		LOAD_HEADER(sbin, offset, const struct sieve_binary_block_index);
	struct sieve_binary_block *block;
	
	if ( record == NULL ) {
		sieve_sys_error("failed to read index record for block %d in binary %s", 
			id, sbin->path);
		return FALSE;
	}
	
	if ( record->id != id ) {
		sieve_sys_error("block index record %d of loaded binary %s "
			"has unexpected id %d", id, sbin->path, record->id);
		return FALSE;
	}
	
	block = sieve_binary_block_create_id(sbin, id);
	block->ext_index = record->ext_id;
	block->offset = record->offset;
	
	return TRUE;
}

static bool _sieve_binary_load_extensions(struct sieve_binary *sbin)
{
	sieve_size_t offset = 0;
	unsigned int i, count;
	bool result = TRUE;
	
	if ( !sieve_binary_block_set_active(sbin, SBIN_SYSBLOCK_EXTENSIONS, NULL) ) 
		return FALSE;

	if ( !sieve_binary_read_unsigned(sbin, &offset, &count) )
		return FALSE;
	
	for ( i = 0; result && i < count; i++ ) {
		T_BEGIN {
			string_t *extension;
			const struct sieve_extension *ext;
			
			if ( sieve_binary_read_string(sbin, &offset, &extension) ) { 
				ext = sieve_extension_get_by_name(str_c(extension));	
			
				if ( ext == NULL ) { 
					sieve_sys_error("loaded binary %s requires unknown extension '%s'", 
						sbin->path, str_sanitize(str_c(extension), 128));
					result = FALSE;					
				} else {
					struct sieve_binary_extension_reg *ereg = NULL;
					
					(void) sieve_binary_extension_register(sbin, ext, &ereg);
					if ( !sieve_binary_read_unsigned(sbin, &offset, &ereg->block_id) )
						result = FALSE;
				}
			}	else
				result = FALSE;
		} T_END;
	}		
		
	return result;
}

static bool _sieve_binary_open(struct sieve_binary *sbin)
{
	bool result = TRUE;
	off_t offset = 0;
	const struct sieve_binary_header *header;
	struct sieve_binary_block *extensions;
	unsigned int i, blk_count;
	
	/* Verify header */
	
	T_BEGIN {
		header = LOAD_HEADER(sbin, &offset, const struct sieve_binary_header);
		if ( header == NULL ) {
			sieve_sys_error("opened binary %s is not even large enough "
				"to contain a header.", sbin->path);
			result = FALSE;

		} else if ( header->magic != SIEVE_BINARY_MAGIC ) {
			if ( header->magic != SIEVE_BINARY_MAGIC_OTHER_ENDIAN ) 
				sieve_sys_error("opened binary %s has corrupted header (0x%08x)", 
					sbin->path, header->magic);
			result = FALSE;

		} else if ( result && (
		  header->version_major != SIEVE_BINARY_VERSION_MAJOR || 
			header->version_minor != SIEVE_BINARY_VERSION_MINOR ) ) {

			/* Binary is of different version. Caller will have to recompile */
			result = FALSE;

		} else if ( result && header->blocks == 0 ) {
			sieve_sys_error("opened binary %s contains no blocks", sbin->path);
			result = FALSE; 

		} else {
			blk_count = header->blocks;
		}
	} T_END;
	
	if ( !result ) return FALSE;
	
	/* Load block index */
	
	for ( i = 0; i < blk_count && result; i++ ) {	
		T_BEGIN {
			if ( !_load_block_index_record(sbin, &offset, i) ) {
				sieve_sys_error(
					"block index record %d of opened binary %s is corrupt", 
					i, sbin->path);
				result = FALSE;
			}
		} T_END;
	}
	
	if ( !result ) return FALSE;
	
	/* Load extensions used by this binary */
	
	T_BEGIN {
		extensions =_load_block(sbin, &offset, 0);
		if ( extensions == NULL ) {
			result = FALSE;
		} else if ( !_sieve_binary_load_extensions(sbin) ) {
			sieve_sys_error("extension block of opened binary %s is corrupt", 
				sbin->path);
			result = FALSE;
		}
	} T_END;
		
	return result;
}

static bool _sieve_binary_load(struct sieve_binary *sbin) 
{	
	bool result = TRUE;
	unsigned int i, blk_count;
	struct sieve_binary_block *block;
	off_t offset;
	
	blk_count = array_count(&sbin->blocks);
	if ( blk_count == 1 ) {
		/* Binary is empty */
		return TRUE;
	}	

	block = sieve_binary_block_get(sbin, SBIN_SYSBLOCK_MAIN_PROGRAM);
	offset = block->offset;
	
	/* Load the other blocks */
	
	for ( i = 1; result && i < blk_count; i++ ) {	
		T_BEGIN {
			if ( _load_block(sbin, &offset, i) == NULL ) {
				sieve_sys_error("block %d of loaded binary %s is corrupt", 
					i, sbin->path);
				result = FALSE;
			}
		} T_END;
	}
				
	return result;
}

struct sieve_binary *sieve_binary_open
	(const char *path, struct sieve_script *script)
{
	unsigned int ext_count, i;
	struct sieve_binary *sbin;
	struct sieve_binary_file *file;
		
	//file = _file_memory_open(path);	
	file = _file_lazy_open(path);
	if ( file == NULL )
		return NULL;
		
	/* Create binary object */
	sbin = sieve_binary_create(script);
	sbin->path = p_strdup(sbin->pool, path);
	sbin->file = file;
	
	if ( !_sieve_binary_open(sbin) ) {
		sieve_binary_unref(&sbin);
		return NULL;
	}
	
	sieve_binary_activate(sbin);
	
	/* Signal open event to extensions */
	ext_count = array_count(&sbin->extensions);	
	for ( i = 0; i < ext_count; i++ ) {
		struct sieve_binary_extension_reg * const *ereg
			= array_idx(&sbin->extensions, i);
		const struct sieve_binary_extension *binext = (*ereg)->binext;
		
		if ( binext != NULL && binext->binary_open != NULL && 
			!binext->binary_open(sbin) ) {
			/* Extension thinks its corrupt */
			sieve_binary_unref(&sbin);
			return NULL;
		}
	}	

	return sbin;
}

bool sieve_binary_load(struct sieve_binary *sbin)
{
	i_assert(sbin->file != NULL);

	/*
	if ( sbin->file->load != NULL && !sbin->file->load(sbin->file) )
		return FALSE;	*/		
	
	if ( !_sieve_binary_load(sbin) ) {
		/* Failed to interpret binary header and/or block structure */
		return FALSE;
	}
	
	return TRUE;
}

/*
 * Up-to-date checking
 */

bool sieve_binary_up_to_date(struct sieve_binary *sbin)
{
	unsigned int ext_count, i;
	
	i_assert(sbin->file != NULL);

	if ( sbin->script == NULL || !sieve_script_older
		(sbin->script, sbin->file->st.st_mtime) )
		return FALSE;
	
	ext_count = array_count(&sbin->extensions);	
	for ( i = 0; i < ext_count; i++ ) {
		struct sieve_binary_extension_reg * const *ereg
			= array_idx(&sbin->extensions, i);
		const struct sieve_binary_extension *binext = (*ereg)->binext;
		
		if ( binext != NULL && binext->binary_up_to_date != NULL && 
			!binext->binary_up_to_date(sbin) )
			return FALSE;
	}
	
	return TRUE;
}

/*
 * Activate the binary (after code generation)
 */
 
void sieve_binary_activate(struct sieve_binary *sbin)
{
	unsigned int i;
	
	(void)sieve_binary_block_set_active(sbin, SBIN_SYSBLOCK_MAIN_PROGRAM, NULL);
	
	/* Load other extensions into binary */
	for ( i = 0; i < array_count(&sbin->linked_extensions); i++ ) {
		struct sieve_binary_extension_reg * const *ereg = 
			array_idx(&sbin->linked_extensions, i);
		const struct sieve_extension *ext = (*ereg)->extension;
		
		if ( ext != NULL && ext->binary_load != NULL )
			ext->binary_load(sbin);
	}
}

/* 
 * Extension handling 
 */

static inline struct sieve_binary_extension_reg *
	sieve_binary_extension_create_reg
(struct sieve_binary *sbin, const struct sieve_extension *ext)
{
	int ext_id = SIEVE_EXT_ID(ext);
	int index = array_count(&sbin->extensions);
	struct sieve_binary_extension_reg *ereg;

	if ( ext_id < 0 ) return NULL;

	ereg = p_new(sbin->pool, struct sieve_binary_extension_reg, 1);
	ereg->index = index;
	ereg->extension = ext;
	
	array_idx_set(&sbin->extensions, (unsigned int) index, &ereg);
	array_idx_set(&sbin->extension_index, (unsigned int) ext_id, &ereg);
	
	return ereg;
}

static inline struct sieve_binary_extension_reg *sieve_binary_extension_get_reg 
(struct sieve_binary *sbin, const struct sieve_extension *ext, bool create) 
{
	int ext_id = SIEVE_EXT_ID(ext);
	struct sieve_binary_extension_reg *reg = NULL;

	if ( ext_id >= 0 && ext_id < (int) array_count(&sbin->extension_index) ) {
		struct sieve_binary_extension_reg * const *ereg = 
			array_idx(&sbin->extension_index, (unsigned int) ext_id);
		
		reg = *ereg;
	}

	/* Register if not known */
	if ( reg == NULL && create )
		return sieve_binary_extension_create_reg(sbin, ext);

	return reg;
}

void sieve_binary_extension_set_context
(struct sieve_binary *sbin, const struct sieve_extension *ext, void *context)
{
	struct sieve_binary_extension_reg *ereg = 
		sieve_binary_extension_get_reg(sbin, ext, TRUE);
	
	if ( ereg != NULL )
		ereg->context = context;
}

const void *sieve_binary_extension_get_context
	(struct sieve_binary *sbin, const struct sieve_extension *ext) 
{
	struct sieve_binary_extension_reg *ereg = 
		sieve_binary_extension_get_reg(sbin, ext, TRUE);

	if ( ereg != NULL ) {
		return ereg->context;
	}
		
	return NULL;
}

void sieve_binary_extension_set
(struct sieve_binary *sbin, const struct sieve_binary_extension *bext,
	void *context)
{
	struct sieve_binary_extension_reg *ereg = 
		sieve_binary_extension_get_reg(sbin, bext->extension, TRUE);
	
	if ( ereg != NULL ) {
		ereg->binext = bext;

		if ( context != NULL )
			ereg->context = context;
	}
}

unsigned int sieve_binary_extension_create_block
(struct sieve_binary *sbin, const struct sieve_extension *ext)
{
	struct sieve_binary_block *block;	
	unsigned int block_id;
	struct sieve_binary_extension_reg *ereg = 
		sieve_binary_extension_get_reg(sbin, ext, TRUE);
	
	i_assert(ereg != NULL);

	block = p_new(sbin->pool, struct sieve_binary_block, 1);
	block->buffer = buffer_create_dynamic(sbin->pool, 64);

	block_id = sieve_binary_block_add(sbin, block);
	
	if ( ereg->block_id < SBIN_SYSBLOCK_LAST )
		ereg->block_id = block_id;
	block->ext_index = ereg->index;
	
	return block_id;
}

unsigned int sieve_binary_extension_get_block
(struct sieve_binary *sbin, const struct sieve_extension *ext)
{
	struct sieve_binary_extension_reg *ereg = 
		sieve_binary_extension_get_reg(sbin, ext, TRUE);
		
	i_assert(ereg != NULL);

	return ereg->block_id;
}

static inline int sieve_binary_extension_register
(struct sieve_binary *sbin, const struct sieve_extension *ext, 
	struct sieve_binary_extension_reg **reg_r) 
{
	struct sieve_binary_extension_reg *ereg;

	if ( (ereg=sieve_binary_extension_get_reg(sbin, ext, FALSE)) == NULL ) {
		ereg = sieve_binary_extension_create_reg(sbin, ext);
		
		if ( ereg == NULL ) return -1;

		array_append(&sbin->linked_extensions, &ereg, 1);
	}

	if ( reg_r != NULL ) *reg_r = ereg;
	return ereg->index;
}

int sieve_binary_extension_link
(struct sieve_binary *sbin, const struct sieve_extension *ext) 
{	
	return sieve_binary_extension_register(sbin, ext, NULL);
}

static inline const struct sieve_extension *_sieve_binary_extension_get_by_index
(struct sieve_binary *sbin, int index) 
{
	struct sieve_binary_extension_reg * const *ext;
	
	if ( index < (int) array_count(&sbin->extensions) ) {
		ext = array_idx(&sbin->extensions, (unsigned int) index);
		
		return (*ext)->extension;
	}
	
	return NULL;
}

const struct sieve_extension *sieve_binary_extension_get_by_index
(struct sieve_binary *sbin, int index)
{
	return _sieve_binary_extension_get_by_index(sbin, index);
}

int sieve_binary_extension_get_index
	(struct sieve_binary *sbin, const struct sieve_extension *ext) 
{
	struct sieve_binary_extension_reg *ereg =
		sieve_binary_extension_get_reg(sbin, ext, FALSE);
	
	return ( ereg == NULL ? -1 : ereg->index );
}

int sieve_binary_extensions_count(struct sieve_binary *sbin) 
{
	return (int) array_count(&sbin->extensions);
}

/*
 * Emission functions
 */

/* Low-level emission functions */

static inline void _sieve_binary_emit_data
(struct sieve_binary *sbin, const void *data, sieve_size_t size) 
{	  
	buffer_append(sbin->data, data, size);
}

static inline void _sieve_binary_emit_byte
(struct sieve_binary *sbin, unsigned char byte)
{
    _sieve_binary_emit_data(sbin, &byte, 1);
}

static inline void _sieve_binary_update_data
(struct sieve_binary *sbin, sieve_size_t address, const void *data, 
	sieve_size_t size) 
{
	buffer_write(sbin->data, address, data, size);
}

sieve_size_t sieve_binary_emit_data
(struct sieve_binary *sbin, const void *data, sieve_size_t size)
{
	sieve_size_t address = _sieve_binary_get_code_size(sbin);

	_sieve_binary_emit_data(sbin, data, size);

	return address;
}

sieve_size_t sieve_binary_emit_byte
(struct sieve_binary *sbin, unsigned char byte) 
{
	sieve_size_t address = _sieve_binary_get_code_size(sbin);

	_sieve_binary_emit_data(sbin, &byte, 1);
	
	return address;
}

void sieve_binary_update_data
(struct sieve_binary *sbin, sieve_size_t address, const void *data, 
	sieve_size_t size) 
{
	_sieve_binary_update_data(sbin, address, data, size);
}

/* Offset emission functions */

sieve_size_t sieve_binary_emit_offset(struct sieve_binary *binary, int offset) 
{
	int i;
	sieve_size_t address = _sieve_binary_get_code_size(binary);

	for ( i = 3; i >= 0; i-- ) {
		char c = (char) (offset >> (i * 8));
		_sieve_binary_emit_data(binary, &c, 1);
	}
	
	return address;
}

void sieve_binary_resolve_offset
	(struct sieve_binary *binary, sieve_size_t address) 
{
	int i;
	int offset = _sieve_binary_get_code_size(binary) - address; 
	
	for ( i = 3; i >= 0; i-- ) {
		char c = (char) (offset >> (i * 8));	
		_sieve_binary_update_data(binary, address + 3 - i, &c, 1);
	}
}

/* Literal emission */

/* FIXME: this integer format is compact, but it might be too slow. 
 */

sieve_size_t sieve_binary_emit_integer
(struct sieve_binary *binary, sieve_number_t integer)
{
	sieve_size_t address = _sieve_binary_get_code_size(binary);
	int i;
	char buffer[sizeof(sieve_number_t) + 1];
	int bufpos = sizeof(buffer) - 1;
  
	buffer[bufpos] = integer & 0x7F;
	bufpos--;
	integer >>= 7;
	while ( integer > 0 ) {
		buffer[bufpos] = integer & 0x7F;
		bufpos--;
		integer >>= 7;  
	}
  
	bufpos++;
	if ( (sizeof(buffer) - bufpos) > 1 ) { 
		for ( i = bufpos; i < ((int) sizeof(buffer) - 1); i++) {
			buffer[i] |= 0x80;
		}
	} 
  
	_sieve_binary_emit_data(binary, buffer + bufpos, sizeof(buffer) - bufpos);

	return address;
}

static inline sieve_size_t sieve_binary_emit_dynamic_data
	(struct sieve_binary *binary, const void *data, sieve_size_t size)
{
	sieve_size_t address = sieve_binary_emit_integer(binary, (sieve_number_t) size);

	_sieve_binary_emit_data(binary, data, size);
  
	return address;
}

sieve_size_t sieve_binary_emit_cstring
	(struct sieve_binary *binary, const char *str)
{
	sieve_size_t address = sieve_binary_emit_dynamic_data
		(binary, (void *) str, (sieve_size_t) strlen(str));
	_sieve_binary_emit_byte(binary, 0);
  
	return address;
}

sieve_size_t sieve_binary_emit_string
	(struct sieve_binary *binary, const string_t *str)
{
	sieve_size_t address = sieve_binary_emit_dynamic_data
		(binary, (void *) str_data(str), (sieve_size_t) str_len(str));
	_sieve_binary_emit_byte(binary, 0);
	
	return address;
}

/*
 * Extension emission
 */

sieve_size_t sieve_binary_emit_extension
(struct sieve_binary *sbin, const struct sieve_extension *ext,
	unsigned int offset)
{
	sieve_size_t address = _sieve_binary_get_code_size(sbin);
	struct sieve_binary_extension_reg *ereg = NULL;

	(void)sieve_binary_extension_register(sbin, ext, &ereg);

	i_assert(ereg != NULL);

   	_sieve_binary_emit_byte(sbin, offset + ereg->index);
	return address;
}

void sieve_binary_emit_extension_object
(struct sieve_binary *sbin, const struct sieve_extension_objects *objs,
	unsigned int code)
{
	if ( objs->count > 1 )
		_sieve_binary_emit_byte(sbin, code);
}

/*
 * Code retrieval
 */
 
#define ADDR_CODE_AT(binary, address) (binary->code[*address])
#define ADDR_DATA_AT(binary, address) ((unsigned char) (binary->code[*address]))
#define ADDR_BYTES_LEFT(binary, address) (binary->code_size - (*address))
#define ADDR_JUMP(address, offset) (*address) += offset

/* Literals */

bool sieve_binary_read_byte
	(struct sieve_binary *binary, sieve_size_t *address, unsigned int *byte_r) 
{	
	if ( ADDR_BYTES_LEFT(binary, address) >= 1 ) {
		if ( byte_r != NULL )
			*byte_r = ADDR_DATA_AT(binary, address);
		ADDR_JUMP(address, 1);
			
		return TRUE;
	}
	
	*byte_r = 0;
	return FALSE;
}

bool sieve_binary_read_code
	(struct sieve_binary *binary, sieve_size_t *address, int *code_r) 
{	
	if ( ADDR_BYTES_LEFT(binary, address) >= 1 ) {
		if ( code_r != NULL )
			*code_r = ADDR_CODE_AT(binary, address);
		ADDR_JUMP(address, 1);
			
		return TRUE;
	}
	
	*code_r = 0;
	return FALSE;
}


bool sieve_binary_read_offset
	(struct sieve_binary *binary, sieve_size_t *address, int *offset_r) 
{
	uint32_t offs = 0;
	
	if ( ADDR_BYTES_LEFT(binary, address) >= 4 ) {
		int i; 
	  
		for ( i = 0; i < 4; i++ ) {
			offs = (offs << 8) + ADDR_DATA_AT(binary, address);
			ADDR_JUMP(address, 1);
		}
	  
		if ( offset_r != NULL )
			*offset_r = (int) offs;
			
		return TRUE;
	}
	
	return FALSE;
}

/* FIXME: might need negative numbers in the future */
bool sieve_binary_read_integer
  (struct sieve_binary *binary, sieve_size_t *address, sieve_number_t *int_r) 
{
	int bits = sizeof(sieve_number_t) * 8;
	*int_r = 0;
  
	if ( ADDR_BYTES_LEFT(binary, address) == 0 )
		return FALSE;
  
	while ( (ADDR_DATA_AT(binary, address) & 0x80) > 0 ) {
		if ( ADDR_BYTES_LEFT(binary, address) > 0 && bits > 0) {
			*int_r |= ADDR_DATA_AT(binary, address) & 0x7F;
			ADDR_JUMP(address, 1);
    
			*int_r <<= 7;
			bits -= 7;
		} else {
			/* This is an error */
			return FALSE;
		}
	}
  
	*int_r |= ADDR_DATA_AT(binary, address) & 0x7F;
	ADDR_JUMP(address, 1);
  
	return TRUE;
}

bool sieve_binary_read_string
(struct sieve_binary *binary, sieve_size_t *address, string_t **str_r) 
{
	unsigned int strlen = 0;
  
	if ( !sieve_binary_read_unsigned(binary, address, &strlen) ) 
		return FALSE;
    	  
	if ( strlen > ADDR_BYTES_LEFT(binary, address) ) 
		return FALSE;
 
 	if ( str_r != NULL )  
		*str_r = t_str_new_const(&ADDR_CODE_AT(binary, address), strlen);
	ADDR_JUMP(address, strlen);
	
	if ( ADDR_CODE_AT(binary, address) != 0 )
		return FALSE;
	
	ADDR_JUMP(address, 1);
  
	return TRUE;
}

bool sieve_binary_read_extension
(struct sieve_binary *sbin, sieve_size_t *address, unsigned int *offset_r,
	const struct sieve_extension **ext_r)
{
	unsigned int code;
	unsigned int offset = *offset_r;
	const struct sieve_extension *ext = NULL;

	if ( ADDR_BYTES_LEFT(sbin, address) <= 0 )
		return FALSE;

	(*offset_r) = code = ADDR_DATA_AT(sbin, address);
	ADDR_JUMP(address, 1);

	if ( code >= offset ) {
		ext = _sieve_binary_extension_get_by_index(sbin, code - offset);
		
		if ( ext == NULL ) 
			return FALSE;
	}

	(*ext_r) = ext;

	return TRUE;
}

const void *sieve_binary_read_extension_object
(struct sieve_binary *sbin, sieve_size_t *address, 
	const struct sieve_extension_objects *objs)
{
	unsigned int code;

	if ( objs->count == 0 ) 
		return NULL;

	if ( objs->count == 1 )
		return objs->objects;

	if ( ADDR_BYTES_LEFT(sbin, address) <= 0 )
		return NULL;

	code = ADDR_DATA_AT(sbin, address);
	ADDR_JUMP(address, 1);	

	if ( code >= objs->count )
		return NULL;

	return ((const void *const *) objs->objects)[code];
}