#include "lib.h"
#include "mempool.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "file-copy.h"

#include "sieve-script-private.h"

#include "sieve-storage.h"
#include "sieve-storage-private.h"
#include "sieve-storage-script.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>

struct sieve_storage_script {
	struct sieve_script script;	

    struct sieve_storage *storage;
};

struct sieve_script *sieve_storage_script_init_from_path
(struct sieve_storage *storage, const char *path, const char *scriptname, 
	bool *exists_r)
{
	pool_t pool;
	struct sieve_storage_script *st_script = NULL;	

	/* Prevent initializing the active script link as a script when it
     * resides in the sieve storage directory.
	 */
	if ( *(storage->link_path) == '\0' ) {
		const char *fname;

		fname = strrchr(path, '/');
		if ( fname == NULL )
			fname = path;
		else
			fname++;

		if ( strcmp(fname, storage->active_fname) == 0 ) {
			if ( exists_r != NULL )
				*exists_r = FALSE;
			return NULL;
		}
	}

	pool = pool_alloconly_create("sieve_storage_script", 4096);	
	st_script = p_new(pool, struct sieve_storage_script, 1);
	st_script->script.pool = pool;
	st_script->storage = storage;

	if ( sieve_script_init(&st_script->script, path, scriptname, 
		sieve_storage_get_error_handler(storage), exists_r) != NULL ) {

		return &st_script->script;
	}

	pool_unref(&pool);

	return NULL;
}

struct sieve_script *sieve_storage_script_init
	(struct sieve_storage *storage, const char *scriptname, bool *exists_r)
{	
	struct sieve_script *script;
	const char *path;

	T_BEGIN {
		path = t_strconcat( storage->dir, "/", scriptname, ".sieve", NULL );

		script = sieve_storage_script_init_from_path
			(storage, path, scriptname, exists_r);
	} T_END;

	return script;
}

const char *sieve_storage_file_get_scriptname
	(const struct sieve_storage *storage ATTR_UNUSED, const char *filename)
{
	const char *ext;

	ext = strrchr(filename, '.');

	if ( ext == NULL || ext == filename || strcmp(ext,".sieve") != 0 ) 
		return NULL;
	
	return t_strdup_until(filename, ext);
}

static const char *sieve_storage_read_active_link
	(struct sieve_storage *storage, bool *not_link)
{
  char linkbuf[PATH_MAX];
  int ret;

	if ( not_link != NULL )
		*not_link = FALSE;

	ret = readlink(storage->active_path, linkbuf, sizeof(linkbuf));

	if ( ret < 0 ) {
		if (errno == EINVAL) {
			/* Our symlink is no symlink. Report 'no active script'.
			 * Activating a script will automatically resolve this, so
			 * there is no need to panic on this one.
			 */
			i_warning
			  ("sieve-storage: Active sieve script symlink %s is no symlink.",
			   storage->active_path);
			if ( not_link != NULL )
				*not_link = TRUE;
			return "";
		}

		if (errno != ENOENT ) {
			/* We do need to panic otherwise */
			sieve_storage_set_critical
			  (storage,
			  	"Performing readlink() on active sieve symlink '%s' failed: %m", 
					storage->active_path);
			return NULL;
		}

		return "";
	}

	/* ret is now assured to be valid, i.e. > 0 */
	return t_strndup(linkbuf, ret);
}

static const char *sieve_storage_parse_link
	(struct sieve_storage *storage, const char *link)
{
	const char *fname, *scriptname, *scriptpath;

	/* Split link into path and filename */
	fname = strrchr(link, '/');
	if ( fname != NULL ) {
		scriptpath = t_strdup_until(link, fname+1);
		fname++;
	} else {
		scriptpath = "";
		fname = link;
	}

	/* Check the script name */
	scriptname = sieve_storage_file_get_scriptname(storage, fname);

	/* Warn if link is deemed to be invalid */
	if ( scriptname == NULL ) {
		i_warning
			("sieve-storage: Active sieve script symlink %s is broken: "
				"invalid scriptname (points to %s).",
				storage->active_path, link);
		return NULL;
	}

	/* Check whether the path is any good */
	if ( strcmp(scriptpath, storage->link_path) != 0 &&
		strcmp(scriptpath, storage->dir) != 0 ) {
		i_warning
			("sieve-storage: Active sieve script symlink %s is broken: "
				"invalid/unknown path to storage (points to %s).",
				storage->active_path, link);
		return NULL; 
	}

	return scriptname;
}

const char *sieve_storage_get_active_scriptname
	(struct sieve_storage *storage)
{
	const char *link, *scriptname;

	/* Read the active link */
	link = sieve_storage_read_active_link(storage, NULL);

	if ( link == NULL || *link == '\0' ) 
		return link;

	/* Parse the link */
	scriptname = sieve_storage_parse_link(storage, link);

	if (scriptname == NULL) {
		/* Obviously someone has been playing with our symlink,
		 * ignore this situation and report 'no active script'.
		 * Activation should fix this situation.
		 */
		return "";
	}

	return scriptname;
}

struct sieve_script *
  sieve_storage_get_active_script(struct sieve_storage *storage, bool *no_active)
{
	bool exists, no_link;
	struct sieve_script *script;
	const char *scriptname, *link;

	*no_active = FALSE;

	/* Read the active link */
	link = sieve_storage_read_active_link(storage, &no_link);
	
	if ( link == NULL )
		/* Error */
		return NULL;

	if ( *link == '\0' )
	{
		if (no_link) {
			/* Try to open the active_path as a regular file */
			return sieve_storage_script_init_from_path
				(storage, storage->active_path, ".dovecot", NULL);
		}

		*no_active = TRUE;
		return NULL;
	}

	/* Parse the link */
	scriptname = sieve_storage_parse_link(storage, link);

	if (scriptname == NULL) {
  		/* Obviously someone has been playing with our symlink,
		 * ignore this situation and report 'no active script'.
		 */
		*no_active = TRUE;
		return NULL;
	}
	
	exists = TRUE;
	script = sieve_storage_script_init(storage, scriptname, &exists);	

	if ( !exists ) {
		i_warning
		  ("sieve-storage: Active sieve script symlink %s "
		   "points to non-existent script (points to %s).",
		   storage->active_path, link);
	}
	
	*no_active = !exists;
	return script;
}

int sieve_storage_script_is_active(struct sieve_script *script)
{
	struct sieve_storage_script *st_script = (struct sieve_storage_script *) script;
	const char *aname;

	t_push();
	
	aname = sieve_storage_get_active_scriptname(st_script->storage);
	
	if (aname == NULL) {
		/* Critical error */
		t_pop();
		return -1;
	}

 	/* Is the requested script active? */
	if ( strcmp(script->name, aname) == 0 ) {
		t_pop();
		return 1;
	}

	t_pop();
	return 0;
}

int sieve_storage_script_delete(struct sieve_script **script) 
{
	struct sieve_storage_script *st_script = (struct sieve_storage_script *) *script;
	struct sieve_storage *storage = st_script->storage;
	int ret = 0;


	/* Is the requested script active? */
	if ( sieve_storage_script_is_active(*script) ) {
		sieve_storage_set_error(storage, "Cannot delete the active sieve script.");
		ret = -1;
	} else {
		ret = unlink((*script)->path);

		if ( ret < 0 ) {
			if ( errno == ENOENT ) 
				sieve_storage_set_error(storage, "Sieve script does not exist.");
			else
				sieve_storage_set_critical(
					storage, "Performing unlink() failed on sieve file '%s': %m", 
					(*script)->path);
		}	
	}

	/* Always deinitialize the script object */
	sieve_script_unref(script);

	return ret;	
}

static bool sieve_storage_rescue_regular_file(struct sieve_storage *storage)
{
	struct stat st;
	
	/* Stat the file */
	if ( lstat(storage->active_path, &st) != 0 ) {
		if ( errno != ENOENT ) {
			sieve_storage_set_critical(storage, 
				"Failed to stat active sieve script symlink (%s): %m.", 
				storage->active_path); 
			return FALSE;	
		} 
		return TRUE;
	}

  	if ( S_ISLNK( st.st_mode ) ) {
		if ( getenv("DEBUG") != NULL )
	    	i_info( "sieve-storage: nothing to rescue %s.", storage->active_path);
    	return TRUE; /* Nothing to rescue */
  	}

	/* Only regular files can be rescued */
	if ( S_ISREG( st.st_mode ) ) {
		const char *dstpath;

 		t_push();

		dstpath = t_strconcat
			( storage->dir, "/dovecot.orig.sieve", NULL );
		if ( file_copy(storage->active_path, dstpath, 1) < 1 ) {
			sieve_storage_set_critical(storage, 
				"Active sieve script file '%s' is a regular file and copying it to the "
				"script storage as '%s' failed. This needs to be fixed manually.",
				storage->active_path, dstpath);
			t_pop();
			return FALSE;	
		} else {
			i_info("sieve-storage: Moved active sieve script file '%s' "
				"to script storage as '%s'.",
				storage->active_path, dstpath); 
			t_pop();
			return TRUE;
    	}
		t_pop();
  	}

	sieve_storage_set_critical( storage,
		"Active sieve script file '%s' is no symlink nor a regular file. "
		"This needs to be fixed manually.", storage->active_path );
	return FALSE;	
}

int sieve_storage_deactivate(struct sieve_storage *storage)
{
	int ret;

	if ( !sieve_storage_rescue_regular_file(storage) ) 
		return -1;

	/* Delete the symlink, so no script is active */
	ret = unlink(storage->active_path);

	if ( ret < 0 ) {
		if ( errno != ENOENT ) {
			sieve_storage_set_error(storage, "sieve_storage_deactivate(): "
				"error on unlink(%s): %m", storage->active_path);
			return -1;
		} else 
		  return 0;
	} 

	return 1;
}

int
sieve_storage_script_activate(struct sieve_script *script)
{
	struct sieve_storage_script *st_script = (struct sieve_storage_script *) script;
	struct sieve_storage *storage = st_script->storage;
	struct stat st;
	const char *active_path_new, *script_path;
	struct timeval *tv, tv_now;
	const char *aname;
	int activated = 0;
	int ret;

	t_push();	

	/* Find out whether there is an active script, but recreate
	 * the symlink either way. This way, any possible error in the symlink
	 * resolves automatically. This step is only necessary to provide a
	 * proper return value indicating whether the script was already active.
	 */
	aname = sieve_storage_get_active_scriptname(storage);

	/* Is the requested script already active? */
	if ( aname == NULL || strcmp(script->name, aname) != 0 ) 
		activated = 1; 

	/* Check the scriptfile we are trying to activate */
	if ( lstat(script->path, &st) != 0 ) {
		sieve_storage_set_critical(storage, 
		  "Stat on sieve script %s failed, but it is to be activated: %m.", 
			script->path);
		t_pop();
		return -1;
	}

	/* Rescue a possible .dovecot.sieve regular file remaining from old 
	 * installations.
	 */
	if ( !sieve_storage_rescue_regular_file(storage) ) {
		/* Rescue failed, manual intervention is necessary */
		t_pop();
		return -1;
	}

	/* Just try to create the symlink first */
	script_path = t_strconcat
	  ( storage->link_path, script->name, ".sieve", NULL );
		
 	ret = symlink(script_path, storage->active_path);

	if ( ret < 0 ) {
		if ( errno == EEXIST ) {
			/* The symlink already exists, try to replace it */
			tv = &ioloop_timeval;

			for (;;) {	
				/* First the new symlink is created with a different filename */
				active_path_new = t_strdup_printf
					("%s-new.%s.P%sM%s.%s.sieve",
						storage->active_path,
						dec2str(tv->tv_sec), my_pid,
						dec2str(tv->tv_usec), my_hostname);

				ret = symlink(script_path, active_path_new);
		
				if ( ret < 0 ) {
					/* If link exists we try again later */
					if ( errno == EEXIST ) {
						/* Wait and try again - very unlikely */
						sleep(2);
						tv = &tv_now;
						if (gettimeofday(&tv_now, NULL) < 0)
							i_fatal("gettimeofday(): %m");
						continue;
					}

					/* Other error, critical */
					sieve_storage_set_critical
						(storage, "Creating symlink() %s to %s failed: %m", 
							active_path_new, script_path);
					t_pop();
					return -1;
				}
	
				/* Link created */
				break;
			}

			/* Replace the existing link. This activates the new script */
			ret = rename(active_path_new, storage->active_path);

			if ( ret < 0 ) {
				/* Failed; created symlink must be deleted */
				(void)unlink(active_path_new);
				sieve_storage_set_critical
					(storage, "Performing rename() %s to %s failed: %m", 
						active_path_new, storage->active_path);
				t_pop();
				return -1;
			}	
		} else {
			/* Other error, critical */
			sieve_storage_set_critical
				(storage,
					"Creating symlink() %s to %s failed: %m",
					storage->active_path, script_path);
			t_pop();
			return -1;
		}
	}

	t_pop();
	return activated;
}



