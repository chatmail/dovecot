/* Copyright (c) 2002-2010 Dovecot Sieve authors, see the included COPYING file
 */

#ifndef __SIEVE_BINARY_H
#define __SIEVE_BINARY_H

#include "lib.h"

#include "sieve-common.h"

/*
 * Binary object
 */
 
struct sieve_binary;

struct sieve_binary *sieve_binary_create_new(struct sieve_script *script);
void sieve_binary_ref(struct sieve_binary *sbin);
void sieve_binary_unref(struct sieve_binary **sbin);

/*
 * Accessors
 */

pool_t sieve_binary_pool(struct sieve_binary *sbin);
struct sieve_script *sieve_binary_script(struct sieve_binary *sbin);
const char *sieve_binary_path(struct sieve_binary *sbin);
bool sieve_binary_script_newer
	(struct sieve_binary *sbin, struct sieve_script *script);
struct sieve_instance *sieve_binary_svinst(struct sieve_binary *sbin);

const char *sieve_binary_script_name(struct sieve_binary *sbin);
const char *sieve_binary_script_path(struct sieve_binary *sbin);

/*
 * Activation after code generation
 */ 
 
void sieve_binary_activate(struct sieve_binary *sbin);

/* 
 * Saving the binary
 */
 
bool sieve_binary_save
	(struct sieve_binary *sbin, const char *path);
	
/* 
 * Loading the binary
 */ 
	
struct sieve_binary *sieve_binary_open
	(struct sieve_instance *svinst, const char *path, 
		struct sieve_script *script);
bool sieve_binary_up_to_date(struct sieve_binary *sbin);
bool sieve_binary_load(struct sieve_binary *sbin);
	
/* 
 * Block management 
 */
 
enum sieve_binary_system_block {
	SBIN_SYSBLOCK_EXTENSIONS,
	SBIN_SYSBLOCK_MAIN_PROGRAM,
	SBIN_SYSBLOCK_LAST
};

bool sieve_binary_block_set_active
	(struct sieve_binary *sbin, unsigned int id, unsigned *old_id_r);
unsigned int sieve_binary_block_create(struct sieve_binary *sbin);
void sieve_binary_block_clear
	(struct sieve_binary *sbin, unsigned int id);
	
/* 
 * Extension support 
 */
 
struct sieve_binary_extension {
	const struct sieve_extension_def *extension;

	bool (*binary_save)
		(const struct sieve_extension *ext, struct sieve_binary *sbin,
			void *context);
	bool (*binary_open)
		(const struct sieve_extension *ext, struct sieve_binary *sbin,
			void *context);	

	void (*binary_free)
		(const struct sieve_extension *ext, struct sieve_binary *sbin,
			void *context);	
	
	bool (*binary_up_to_date)
		(const struct sieve_extension *ext, struct sieve_binary *sbin,
			void *context);	
};
 
void sieve_binary_extension_set_context
	(struct sieve_binary *sbin, const struct sieve_extension *ext, void *context);
const void *sieve_binary_extension_get_context
	(struct sieve_binary *sbin, const struct sieve_extension *ext);
	
void sieve_binary_extension_set
	(struct sieve_binary *sbin, const struct sieve_extension *ext,
		const struct sieve_binary_extension *bext, void *context);

unsigned int sieve_binary_extension_create_block
	(struct sieve_binary *sbin, const struct sieve_extension *ext);
unsigned int sieve_binary_extension_get_block
(struct sieve_binary *sbin, const struct sieve_extension *ext);

int sieve_binary_extension_link
	(struct sieve_binary *sbin, const struct sieve_extension *ext);
const struct sieve_extension *sieve_binary_extension_get_by_index
	(struct sieve_binary *sbin, int index);
int sieve_binary_extension_get_index
	(struct sieve_binary *sbin, const struct sieve_extension *ext);
int sieve_binary_extensions_count(struct sieve_binary *sbin);

	
/* 
 * Code emission 
 */
 
/* Low-level emission functions */

sieve_size_t sieve_binary_emit_data
	(struct sieve_binary *binary, const void *data, sieve_size_t size);
sieve_size_t sieve_binary_emit_byte
	(struct sieve_binary *binary, unsigned char byte);
void sieve_binary_update_data
	(struct sieve_binary *binary, sieve_size_t address, const void *data, 
		sieve_size_t size);
sieve_size_t sieve_binary_get_code_size(struct sieve_binary *binary);

/* Offset emission functions */

sieve_size_t sieve_binary_emit_offset
	(struct sieve_binary *binary, int offset);
void sieve_binary_resolve_offset
	(struct sieve_binary *binary, sieve_size_t address);

/* Literal emission functions */

sieve_size_t sieve_binary_emit_integer
	(struct sieve_binary *binary, sieve_number_t integer);
sieve_size_t sieve_binary_emit_string
	(struct sieve_binary *binary, const string_t *str);
sieve_size_t sieve_binary_emit_cstring
	(struct sieve_binary *binary, const char *str);

static inline sieve_size_t sieve_binary_emit_unsigned
	(struct sieve_binary *binary, unsigned int count)
{
	return sieve_binary_emit_integer(binary, count);
}


/* Extension emission functions */

sieve_size_t sieve_binary_emit_extension
	(struct sieve_binary *sbin, const struct sieve_extension *ext,
		unsigned int offset);
void sieve_binary_emit_extension_object
	(struct sieve_binary *sbin, const struct sieve_extension_objects *objs,
    	unsigned int code);

/* 
 * Code retrieval 
 */

/* Literals */
bool sieve_binary_read_byte
	(struct sieve_binary *binary, sieve_size_t *address, unsigned int *byte_r);
bool sieve_binary_read_code
	(struct sieve_binary *binary, sieve_size_t *address, signed int *code_r);
bool sieve_binary_read_offset
	(struct sieve_binary *binary, sieve_size_t *address, int *offset_r);
bool sieve_binary_read_integer
  (struct sieve_binary *binary, sieve_size_t *address, sieve_number_t *int_r); 
bool sieve_binary_read_string
  (struct sieve_binary *binary, sieve_size_t *address, string_t **str_r);

static inline bool sieve_binary_read_unsigned
  (struct sieve_binary *binary, sieve_size_t *address, unsigned int *count_r)
{
	sieve_number_t integer;

	if ( !sieve_binary_read_integer(binary, address, &integer) )
		return FALSE;

	*count_r = integer;

	return TRUE;
}

/* Extension */
bool sieve_binary_read_extension
	(struct sieve_binary *sbin, sieve_size_t *address, unsigned int *offset_r,
		const struct sieve_extension **ext_r);
const void *sieve_binary_read_extension_object
	(struct sieve_binary *binary, sieve_size_t *address,
    	const struct sieve_extension_objects *objs);

#endif
