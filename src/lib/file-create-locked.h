#ifndef FILE_CREATE_LOCKED_H
#define FILE_CREATE_LOCKED_H

#include "file-lock.h"

struct file_create_settings {
	/* 0 = try locking without waiting */
	unsigned int lock_timeout_secs;

	enum file_lock_method lock_method;
	/* 0 = 0600 */
	int mode;
	/* 0 = default */
	uid_t uid;
	/* 0 = default */
	gid_t gid;
	const char *gid_origin;
};

/* Either open an existing file and lock it, or create the file locked.
   The creation is done by creating a temp file and link()ing it to path.
   If link() fails, opening is retried again. Returns fd on success,
   -1 on error. errno is preserved for the last failed syscall, so most
   importantly ENOENT could mean that the directory doesn't exist and EAGAIN
   means locking timed out. */
int file_create_locked(const char *path, const struct file_create_settings *set,
		       struct file_lock **lock_r, bool *created_r,
		       const char **error_r);

#endif
