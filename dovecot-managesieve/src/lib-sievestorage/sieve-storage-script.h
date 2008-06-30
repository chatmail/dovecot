#ifndef __SIEVE_FILE_H
#define __SIEVE_FILE_H

#include "sieve-script.h"

#include "sieve-storage.h"

struct sieve_script *sieve_storage_script_init
    (struct sieve_storage *storage, const char *scriptname, bool *exists_r);

const char *sieve_storage_file_get_scriptname
	(const struct sieve_storage *storage, const char *filename);

const char *
	sieve_storage_get_active_scriptname(struct sieve_storage *storage);

struct sieve_script *
	sieve_storage_get_active_script(struct sieve_storage *storage, bool *no_active);

int sieve_storage_script_is_active(struct sieve_script *script);

int sieve_storage_script_delete(struct sieve_script **script);

int sieve_storage_deactivate(struct sieve_storage *storage);

int sieve_storage_script_activate(struct sieve_script *script);

#endif

