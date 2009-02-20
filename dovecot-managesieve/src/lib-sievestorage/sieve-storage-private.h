#ifndef __SIEVE_STORAGE_PRIVATE_H
#define __SIEVE_STORAGE_PRIVATE_H

#include "sieve.h"
#include "sieve-error-private.h"

#include "sieve-storage.h"


enum sieve_storage_flags {
	/* Print debugging information while initializing the storage */
	SIEVE_STORAGE_FLAG_DEBUG     = 0x01,
	/* Use CRLF linefeeds when saving mails. */
	SIEVE_STORAGE_FLAG_SAVE_CRLF   = 0x02,
};

#define SIEVE_READ_BLOCK_SIZE (1024*8)

struct sieve_storage;

struct sieve_storage_ehandler {
	struct sieve_error_handler handler;
	struct sieve_storage *storage;
};

/* All methods returning int return either TRUE or FALSE. */
struct sieve_storage {
	pool_t pool;
	char *name;
	char *dir;

	/* Private */	
	char *active_path;
	char *active_fname;
	char *link_path;
	char *error;
	char *user; /* name of user accessing the storage */

	struct sieve_error_handler *ehandler;

	enum sieve_storage_flags flags;
};

struct sieve_script *sieve_storage_script_init_from_path
(struct sieve_storage *storage, const char *path, bool *exists_r);

#endif

