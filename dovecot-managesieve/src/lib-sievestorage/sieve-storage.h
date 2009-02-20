#ifndef __SIEVE_STORAGE_H
#define __SIEVE_STORAGE_H

struct sieve_storage *sieve_storage_create_from_mail(const char *data, const char *user);
struct sieve_storage *sieve_storage_create(const char *data, const char *user);
void sieve_storage_free(struct sieve_storage *storage);

struct sieve_error_handler *sieve_storage_get_error_handler(struct sieve_storage *storage);

/* Set error message in storage. Critical errors are logged with i_error(),
   but user sees only "internal error" message. */
void sieve_storage_clear_error(struct sieve_storage *storage);
void sieve_storage_set_error(struct sieve_storage *storage,
	const char *fmt, ...) ATTR_FORMAT(2, 3);
void sieve_storage_set_critical(struct sieve_storage *storage,
	const char *fmt, ...) ATTR_FORMAT(2, 3);
void sieve_storage_set_internal_error(struct sieve_storage *storage);

const char *sieve_storage_get_last_error(struct sieve_storage *storage);

#endif
