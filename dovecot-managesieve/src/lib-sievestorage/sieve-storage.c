#include "lib.h"
#include "home-expand.h"
#include "ioloop.h"
#include "mkdir-parents.h"

#include "sieve.h"
#include "sieve-error-private.h"

#include "sieve-storage-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#define SIEVE_SCRIPT_PATH "~/.dovecot.sieve"

#define CREATE_MODE 0770 /* umask() should limit it more */

#define CRITICAL_MSG \
  "Internal error occured. Refer to server log for more information."
#define CRITICAL_MSG_STAMP CRITICAL_MSG " [%Y-%m-%d %H:%M:%S]"

static void sieve_storage_verror
	(struct sieve_error_handler *ehandler ATTR_UNUSED, 
		const char *location ATTR_UNUSED, const char *fmt, va_list args);

static const char *sieve_get_active_script_path(void)
{
  const char *script_path, *home;

  home = getenv("HOME");

  /* userdb may specify Sieve path */
  script_path = getenv("SIEVE");
  if (script_path != NULL) {
	if (*script_path == '\0') {
		/* disabled */
		return NULL;
	}

    if ( *script_path != '/' && *script_path != '~') {
      /* relative path. change to absolute. */
      script_path = t_strconcat(getenv("HOME"), "/",  
        script_path, NULL);
    }
  } else {
    if (home == NULL) {
      /* we must have a home directory */
      i_error("sieve-storage: userdb(%s) didn't return a home directory or "
        "sieve script location, can't find it",
        getenv("USER"));
      return NULL;
    }

    script_path = SIEVE_SCRIPT_PATH;
  }

  /* No need to check for existance here */

  return script_path;
}

/* Obtain the directory for script storage from the mail location
 */
static const char *sieve_storage_get_dir_from_mail(const char *data)
{
	bool debug = (getenv("DEBUG") != NULL);
	struct stat st;
	size_t len;
	const char *root_dir, *dir, *p, *d;

	root_dir = dir = d = NULL;

	if (debug)
		i_info("sieve-storage: using mail-data: %s", data);

	/* check if we're in the form of mailformat:data
	   (eg. maildir:Maildir) */
	p = data;
	while (i_isalnum(*p)) p++;
	
	if (*p == ':') {
		d = p+1;
	} else {
		d = data;
	}

	if (d == NULL || *d == '\0') {
		/* Ok, this is bad. Check whether we might be chrooted, bail out otherwise */
		if (access("/sieve", R_OK|W_OK|X_OK) == 0)
			root_dir = "/";
		else {
			i_error("sieve-storage: sieve storage directory not given and mail root provides no alternative.");
            return NULL;
		}
	} else {
		/* <scriptdir> */
		p = strchr(d, ':');
		if (p == NULL)
			/* No additional parameters */
			root_dir = d;
		else {
			dir = t_strdup_until(d, p);
 
			do {
				p++;
				/* Use control dir as script dir if specified */
				if (strncmp(p, "CONTROL=", 8) == 0)
					root_dir = t_strcut(p+8, ':');
				p = strchr(p, ':');
			} while (p != NULL);
			
			if ( root_dir == NULL || *root_dir == '\0' )
				root_dir = dir;
		}
	}

	/* Not found */
	if ( root_dir == NULL || *root_dir == '\0' ) {
		if (debug)
            i_info("sieve-storage: couldn't find root dir from mail-data.");
        return NULL;
    }

	/* Strip trailing '/' */
    len = strlen(root_dir);
    if (root_dir[len-1] == '/')
        root_dir = t_strndup(root_dir, len-1);

	/* Superior mail directory must exist; it is never auto-created by the 
	 * sieve-storage.
 	 */
	if (stat(root_dir, &st) < 0 ) {
		if ( errno != ENOENT ) {
			i_error("sieve-storage: root dir from mail data: stat(%s) failed: %m", root_dir);
			return NULL;
		} else {
			i_error("sieve-storage: root directory specified by mail data does not exist: %s", root_dir);
			return NULL;
		}
	} 

	/* Never store scripts directly in the root of the mail or mail:CONTROl directory.
	 */
	root_dir = t_strconcat( root_dir, "/sieve", NULL );

	return root_dir;
}

static const char *sieve_storage_get_relative_link_path
	(const char *active_path, const char *storage_dir) 
{
	const char *link_path, *p;
	size_t pathlen;
	
	/* Determine to what extent the sieve storage and active script 
	 * paths match up. This enables the managed symlink to be short and the 
	 * sieve storages can be moved around without trouble (if the active 
	 * script path is common to the script storage).
	 */		
	p = strrchr(active_path, '/');
	if ( p == NULL ) {
		link_path = storage_dir;
	} else { 
		pathlen = p - active_path;

		if ( strncmp( active_path, storage_dir, pathlen ) == 0 &&
			(storage_dir[pathlen] == '/' || storage_dir[pathlen] == '\0') ) 
		{
			if ( storage_dir[pathlen] == '\0' ) 
				link_path = ""; 
			else 
				link_path = storage_dir + pathlen + 1;
		} else 
			link_path = storage_dir;
	}

	/* Add trailing '/' when link path is not empty 
	 */
	pathlen = strlen(link_path);
    if ( pathlen != 0 && link_path[pathlen-1] != '/')
        return t_strconcat(link_path, "/", NULL);

	return t_strdup(link_path);
}

struct sieve_storage *sieve_storage_create_from_mail(const char *data, const char *user)
{
	struct sieve_storage *storage;
	const char *storage_dir;

	t_push();

	storage_dir = sieve_storage_get_dir_from_mail(data);
	if (storage_dir == NULL) {
		if (getenv("DEBUG") != NULL)
			i_info("sieve-storage: failed to obtain storage directory from mail-data.");
		t_pop();
		return NULL;
	} 

	storage = sieve_storage_create(storage_dir, user);

	t_pop();

	return storage;
}

struct sieve_storage *sieve_storage_create(const char *data, const char *user)
{
	bool debug = (getenv("DEBUG") != NULL);
	pool_t pool;
	struct sieve_storage *storage;
	const char *home, *tmp_dir, *link_path, *path;
	const char *active_path, *active_fname, *storage_dir;

	t_push();

	/* Find out where the active script is stored (e.g. ~/.dovecot.sieve) */

	active_path = sieve_get_active_script_path();
	if (active_path == NULL) {
		t_pop();
		return NULL;
	}

	if (debug)
		i_info("sieve-storage: using active sieve script path: %s", active_path);

	/* Get the filename for the active script link */
	active_fname = strrchr(active_path, '/');
	if ( active_fname == NULL ) 
		active_fname = active_path;
	else
		active_fname++;

	if ( *active_fname == '\0' ) {	
		/* Link cannot be just a path */
		i_error("sieve-storage: Path to active symlink must include the link's filename. Path is: %s", 
			active_path);

		t_pop();
		return NULL;
	}

	if (debug)
		i_info("sieve-storage: using active sieve script path: %s", active_path);

	/* Find out where to put the script storage */

	storage_dir = NULL;

	if ( data == NULL || *data == '\0' ) {
		/* We'll need to figure out the storage location ourself.
		 *
         * It's $HOME/sieve or /sieve when (presumed to be) chrooted.  
		 */
		home = getenv("HOME");
        if ( home != NULL && *home != '\0' ) {
			size_t len;

            if (access(home, R_OK|W_OK|X_OK) == 0) {
                if (debug) {
                    i_info("sieve-storage: root exists (%s)",
                           home);
                }

				/* Check for trailing '/' */
    			len = strlen(home);
    			if (home[len-1] == '/')
            		path = t_strconcat(home, "sieve", NULL);
				else
            		path = t_strconcat(home, "/sieve", NULL);
			
                storage_dir = path;
            } else {
                if (debug) {
                    i_info("sieve-storage: access(%s, rwx): "
                           "failed: %m", home);
                }
            }
		} else {
			if (debug)
                i_info("sieve-storage: HOME not set");
        }

		if (access("/sieve", R_OK|W_OK|X_OK) == 0) {
            storage_dir = "/sieve";
			if (debug)
				i_info("sieve-storage: /sieve exists, assuming chroot");
        }
	} else {
		storage_dir = data;
	}

	if (storage_dir == NULL || *storage_dir == '\0') {
        if (debug)
            i_info("sieve-storage: couldn't find storage dir");
        return NULL;
    }

	if (debug)
 		i_info("sieve-storage: using sieve script storage directory: %s", storage_dir);    

	/* Expand home directoties in path */
	storage_dir = home_expand(storage_dir);
	active_path = home_expand(active_path);

	/* Ensure sieve local directory structure exists (full autocreate):
	 *  This currently currently only consists of a ./tmp direcory
	 */
	tmp_dir = t_strconcat( storage_dir, "/tmp", NULL );	
	if (mkdir_parents(tmp_dir, CREATE_MODE) < 0 && errno != EEXIST) {
		i_error("sieve-storage: mkdir_parents(%s, CREATE_MODE) failed: %m", tmp_dir);
		t_pop();
		return NULL;
	}

	/* Create storage object */
	pool = pool_alloconly_create("sieve-storage", 512+256);
    storage = p_new(pool, struct sieve_storage, 1);	
	storage->pool = pool;
	storage->dir = p_strdup(pool, storage_dir);
	storage->user = p_strdup(pool, user);
	storage->active_path = p_strdup(pool, active_path);
	storage->active_fname = p_strdup(pool, active_fname);

	/* Get the path to be prefixed to the script name in the symlink pointing 
	 * to the active script.
	 */
	link_path = sieve_storage_get_relative_link_path
		(storage->active_path, storage->dir);
	if (debug)
		i_info("sieve-storage: relative path to sieve storage in active link: %s", link_path);

	storage->link_path = p_strdup(pool, link_path);

	t_pop();

	return storage;
}

void sieve_storage_free(struct sieve_storage *storage)
{
	sieve_error_handler_unref(&storage->ehandler);

	pool_unref(&storage->pool);
}

/* Error handling */

struct sieve_error_handler *sieve_storage_get_error_handler(struct sieve_storage *storage)
{
	struct sieve_storage_ehandler *ehandler;

	if ( storage->ehandler == NULL ) {
		pool_t pool = pool_alloconly_create("sieve_storage_ehandler", 512);
		ehandler = p_new(pool, struct sieve_storage_ehandler,1);
		sieve_error_handler_init(&ehandler->handler, pool, 1);

		ehandler->handler.verror = sieve_storage_verror;
		ehandler->storage = storage;
		
		storage->ehandler = (struct sieve_error_handler *) ehandler;
	}

	return storage->ehandler;
}

static void sieve_storage_verror
(struct sieve_error_handler *ehandler, const char *location ATTR_UNUSED,
    const char *fmt, va_list args)
{
	struct sieve_storage_ehandler *sehandler = (struct sieve_storage_ehandler *) ehandler; 
	struct sieve_storage *storage = sehandler->storage;

	sieve_storage_clear_error(storage);
	
	if (fmt != NULL) {
        storage->error = i_strdup_vprintf(fmt, args);
    }
}

void sieve_storage_clear_error(struct sieve_storage *storage)
{
	i_free(storage->error);
	storage->error = NULL;
}

void sieve_storage_set_error(struct sieve_storage *storage, const char *fmt, ...)
{
	va_list va;

	sieve_storage_clear_error(storage);

	if (fmt != NULL) {
		va_start(va, fmt);
		storage->error = i_strdup_vprintf(fmt, va);
		va_end(va);
	}
}

void sieve_storage_set_internal_error(struct sieve_storage *storage)
{
	struct tm *tm;
	char str[256];

	tm = localtime(&ioloop_time);

	i_free(storage->error);
	storage->error =
	  strftime(str, sizeof(str), CRITICAL_MSG_STAMP, tm) > 0 ?
	  i_strdup(str) : i_strdup(CRITICAL_MSG);
}

void sieve_storage_set_critical(struct sieve_storage *storage,
             const char *fmt, ...)
{
	va_list va;
	
	sieve_storage_clear_error(storage);
	if (fmt != NULL) {
		va_start(va, fmt);
		i_error("sieve-storage: %s", t_strdup_vprintf(fmt, va));
		va_end(va);
		
		/* critical errors may contain sensitive data, so let user
		   see only "Internal error" with a timestamp to make it
		   easier to look from log files the actual error message. */
		sieve_storage_set_internal_error(storage);
	}
}

const char *sieve_storage_get_last_error(struct sieve_storage *storage)
{
  /* We get here only in error situations, so we have to return some
     error. If storage->error is NULL, it means we forgot to set it at
     some point.. */
  return storage->error != NULL ? storage->error : "Unknown error";
}


