/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "restrict-access.h"
#include "eacces-error.h"

#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

static bool is_in_group(gid_t gid)
{
	const gid_t *gids;
	unsigned int i, count;

	if (getegid() == gid)
		return TRUE;

	gids = restrict_get_groups_list(&count);
	for (i = 0; i < count; i++) {
		if (gids[i] == gid)
			return TRUE;
	}
	return FALSE;
}

static int test_access(const char *path, int mode, string_t *errmsg)
{
	struct stat st;

	if (getuid() == geteuid()) {
		if (access(path, mode) == 0)
			return 0;

		if (errno != EACCES) {
			str_printfa(errmsg, " access(%s, %d) failed: %m",
				    path, mode);
		}
		return -1;
	} 

	/* access() uses real uid, not effective uid.
	   we'll have to do these checks manually. */
	switch (mode) {
	case X_OK:
		if (stat(t_strconcat(path, "/test", NULL), &st) == 0)
			return 0;
		if (errno == ENOENT || errno == ENOTDIR)
			return 0;
		if (errno != EACCES)
			str_printfa(errmsg, " stat(%s/test) failed: %m", path);
		return -1;
	case R_OK:
		mode = 04;
		break;
	case W_OK:
		mode = 02;
		break;
	default:
		i_unreached();
	}

	if (stat(path, &st) < 0) {
		str_printfa(errmsg, " stat(%s) failed: %m", path);
		return -1;
	}

	if (st.st_uid == geteuid())
		st.st_mode = (st.st_mode & 0700) >> 6;
	else if (is_in_group(st.st_gid))
		st.st_mode = (st.st_mode & 0070) >> 3;
	else
		st.st_mode = (st.st_mode & 0007);

	if ((st.st_mode & mode) != 0)
		return 0;
	errno = EACCES;
	return -1;
}

static const char *
eacces_error_get_full(const char *func, const char *path, bool creating)
{
	const char *prev_path = path, *dir, *p;
	const struct passwd *pw;
	const struct group *group;
	string_t *errmsg;
	struct stat st, dir_st;
	char cwd[PATH_MAX];
	int orig_errno, ret = -1;

	orig_errno = errno;
	errmsg = t_str_new(256);
	str_printfa(errmsg, "%s(%s)", func, path);
	if (*path != '/') {
		dir = getcwd(cwd, sizeof(cwd));
		if (dir != NULL)
			str_printfa(errmsg, " in directory %s", dir);
	}
	str_printfa(errmsg, " failed: Permission denied (euid=%s",
		    dec2str(geteuid()));

	pw = getpwuid(geteuid());
	if (pw != NULL)
		str_printfa(errmsg, "(%s)", pw->pw_name);
	else
		str_append(errmsg, "(<unknown>)");

	str_printfa(errmsg, " egid=%s", dec2str(getegid()));
	group = getgrgid(getegid());
	if (group != NULL)
		str_printfa(errmsg, "(%s)", group->gr_name);
	else
		str_append(errmsg, "(<unknown>)");

	dir = "/";
	while ((p = strrchr(prev_path, '/')) != NULL) {
		dir = t_strdup_until(prev_path, p);
		ret = stat(dir, &st);
		if (ret == 0)
			break;
		if (errno == EACCES) {
			/* see if we have access to parent directory */
		} else if (errno == ENOENT && creating) {
			/* probably mkdir_parents() failed here, find the first
			   parent directory we couldn't create */
		} else {
			/* some other error, can't handle it */
			str_printfa(errmsg, " stat(%s) failed: %m", dir);
			break;
		}
		prev_path = dir;
		dir = "/";
		dir_st = st;
	}

	if (ret == 0) {
		/* dir is the first parent directory we can stat() */
		if (test_access(dir, X_OK, errmsg) < 0) {
			if (errno == EACCES)
				str_printfa(errmsg, " missing +x perm: %s", dir);
		} else if (creating && test_access(dir, W_OK, errmsg) < 0) {
			if (errno == EACCES)
				str_printfa(errmsg, " missing +w perm: %s", dir);
		} else if (prev_path == path &&
			   test_access(path, R_OK, errmsg) < 0) {
			if (errno == EACCES)
				str_printfa(errmsg, " missing +r perm: %s", path);
		} else if (!creating && test_access(path, W_OK, errmsg) < 0) {
			/* this produces a wrong error if the operation didn't
			   actually need write permissions, but we don't know
			   it here.. */
			if (errno == EACCES)
				str_printfa(errmsg, " missing +w perm: %s", path);
		} else
			str_printfa(errmsg, " UNIX perms appear ok, "
				    "some security policy wrong?");
	}
	str_append_c(errmsg, ')');
	errno = orig_errno;
	return str_c(errmsg);
}

const char *eacces_error_get(const char *func, const char *path)
{
	return eacces_error_get_full(func, path, FALSE);
}

const char *eacces_error_get_creating(const char *func, const char *path)
{
	return eacces_error_get_full(func, path, TRUE);
}

const char *eperm_error_get_chgrp(const char *func, const char *path,
				  gid_t gid, const char *gid_origin)
{
	string_t *errmsg;
	const struct group *group;
	int orig_errno = errno;

	errmsg = t_str_new(256);
	
	str_printfa(errmsg, "%s(%s, -1, %s", func, path, dec2str(gid));
	group = getgrgid(gid);
	if (group != NULL)
		str_printfa(errmsg, "(%s)", group->gr_name);

	str_printfa(errmsg, ") failed: Operation not permitted (egid=%s",
		    dec2str(getegid()));
	group = getgrgid(getegid());
	if (group != NULL)
		str_printfa(errmsg, "(%s)", group->gr_name);
	if (gid_origin != NULL)
		str_printfa(errmsg, ", group based on %s", gid_origin);
	str_append_c(errmsg, ')');
	errno = orig_errno;
	return str_c(errmsg);
}