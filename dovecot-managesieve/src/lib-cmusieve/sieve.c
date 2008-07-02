/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "libsieve/sieve_interface.h"

#include "sieve.h"
#include "sieve-script.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

/* data per script */
typedef struct script_data {
	struct sieve_error_handler *ehandler;
} script_data_t;

static sieve_interp_t *_interp;

struct et_list *_et_list = NULL;

static int
cmu_sieve_compile(script_data_t *sdata, const char *script_path,
		      const char *compiled_path);

/* gets the header "head" from msg. */
static int getheader
(void *v ATTR_UNUSED, const char *phead ATTR_UNUSED, const char ***body ATTR_UNUSED)
{
	return SIEVE_OK;
}

static int getsize(void *mc ATTR_UNUSED, int *size ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int getenvelope
(void *mc ATTR_UNUSED, const char *field ATTR_UNUSED, 
	const char ***contents ATTR_UNUSED)
{
	return SIEVE_OK;
}

static int getbody
(void *mc ATTR_UNUSED, const char **content_types ATTR_UNUSED,
	int decode_to_plain ATTR_UNUSED, sieve_bodypart_t **parts_r ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int getinclude(void *sc, const char *script, int isglobal,
		      char *fname, size_t size)
{
	script_data_t *sdata = (script_data_t *) sc;
	const char *script_path, *compiled_path, *home, *script_dir;
	int ret;

	if (strchr(script, '/') != NULL) {
		i_info("include: '/' not allowed in script names (%s)",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}

	if (isglobal) {
		script_dir = getenv("SIEVE_GLOBAL_DIR");
		if (script_dir == NULL) {
			i_info("include: global_script_dir not set "
			       "(wanted script %s)", str_sanitize(script, 80));
			return SIEVE_FAIL;
		}
		script_path = t_strdup_printf("%s/%s", script_dir, script);
	} else {
		home = getenv("SIEVE_DIR");
		if (home == NULL)
			home = getenv("HOME");
		if (home == NULL) {
			i_info("include: sieve_dir and home not set "
			       "(wanted script %s)", str_sanitize(script, 80));
			return SIEVE_FAIL;
		}
		script_path = t_strdup_printf("%s/%s", home, script);
	}

	compiled_path = t_strconcat(script_path, "c", NULL);
	ret = cmu_sieve_compile(sdata, script_path, compiled_path);
	if (ret < 0) {
		i_info("include: Error compiling script '%s'",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}
	if (ret == 0) {
		i_info("include: Script not found: '%s'",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}

	if (i_strocpy(fname, compiled_path, size) < 0) {
		i_info("include: Script path too long: '%s'",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}
	return SIEVE_OK;
}

static int sieve_redirect
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED,  void *sc ATTR_UNUSED, 
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
	return SIEVE_OK;
}

static int sieve_discard
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED, void *sc ATTR_UNUSED, 
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int sieve_reject
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED, void *sc ATTR_UNUSED, 
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int sieve_fileinto
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED, void *sc ATTR_UNUSED, 
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int sieve_keep
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED, void *sc ATTR_UNUSED, 
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int sieve_notify
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED, void *sc ATTR_UNUSED,
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int autorespond
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED, void *sc ATTR_UNUSED,
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
    return SIEVE_OK;
}

static int send_response
(void *ac ATTR_UNUSED, void *ic ATTR_UNUSED, void *sc ATTR_UNUSED, 
	void *mc ATTR_UNUSED, const char **errmsg ATTR_UNUSED)
{
	return SIEVE_OK;
}

/* vacation support */
sieve_vacation_t vacation = {
    1,				/* min response */
    31,				/* max response */
    &autorespond,		/* autorespond() */
    &send_response		/* send_response() */
};

/* imapflags support */
static char *markflags[] = { "\\flagged" };
static sieve_imapflags_t mark = { markflags, 1 };

static int sieve_parse_error_handler(int lineno, const char *msg, 
				     void *ic ATTR_UNUSED,
				     void *sc)
{
    script_data_t *sd = (script_data_t *) sc;

	sieve_error(sd->ehandler, t_strdup_printf("line %d", lineno), "%s", msg);
    return SIEVE_OK;
}

static int sieve_execute_error_handler(const char *msg, 
				       void *ic ATTR_UNUSED,
				       void *sc ATTR_UNUSED,
				       void *mc ATTR_UNUSED)
{
    i_info("sieve runtime error: %s", msg);
    return SIEVE_OK;
}
 
static int
cmu_sieve_compile(script_data_t *sdata, const char *script_path,
		      const char *compiled_path)
{
	struct stat st, st2;
	sieve_script_t *script;
	bytecode_info_t *bc;
	const char *temp_path;
	FILE *f;
	int fd, ret;

	if (stat(script_path, &st) < 0) {
		if (errno == ENOENT) {
			if (getenv("DEBUG") != NULL) {
				i_info("cmusieve: Script not found: %s",
				       script_path);
			}
			return 0;
		}
		i_error("cmusieve: stat(%s) failed: %m", script_path);
		return -1;
	}
	if ( compiled_path != NULL ) {
		if (stat(compiled_path, &st2) < 0) {
			if (errno != ENOENT) {
				i_error("cmusieve: stat(%s) failed: %m", script_path);
				return -1;
			}
		} else {
			if (st.st_mtime < st2.st_mtime)
				return 1;
		}
	}

	/* need to compile */
	f = fopen(script_path, "r");
	if (f == NULL) {
		i_error("cmusieve: fopen(%s) failed: %m", script_path);
		return -1;
	}

	ret = sieve_script_parse(_interp, f, sdata, &script);
	if (ret != SIEVE_OK) {
		if ( sieve_get_errors(sdata->ehandler) == 0 ) {
			sieve_error(sdata->ehandler, "unknown location", 
				"parse error %d", ret);
		}
		return -1;
	} 

	if (sieve_generate_bytecode(&bc, script) < 0) {
		i_error("sieve_generate_bytecode() failed");
		return -1;
	}

	if ( compiled_path != NULL ) {
		/* write to temp file */
		temp_path = t_strconcat(compiled_path, ".tmp", NULL);
		fd = open(temp_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
		if(fd == -1) {
			i_error("cmusieve: open(%s) failed: %m", temp_path);
			return -1;
		}

		if (sieve_emit_bytecode(fd, bc) < 0) {
			i_error("cmusieve: sieve_emit_bytecode() failed");
			return -1;
		}

		if (close(fd) < 0)
			i_error("cmusieve: close() failed: %m");

		/* and finally replace the script */
		if (rename(temp_path, compiled_path) < 0) {
			i_error("cmusieve: rename(%s, %s) failed: %m", temp_path, compiled_path);
			return -1;
		}
	}
	return 1;
}

struct sieve_binary *sieve_compile_script
    (struct sieve_script *script, struct sieve_error_handler *ehandler)
{
	script_data_t sdata;
	const char *script_path = sieve_script_path(script);
	const char *compiled_path;
	int ret;

	memset(&sdata, 0, sizeof(sdata));
	sdata.ehandler = ehandler;

	compiled_path = t_strconcat(script_path, "c", NULL);
	ret = cmu_sieve_compile(&sdata, script_path, NULL);
	if (ret <= 0)
		return NULL;

	return (struct sieve_binary *) 1; 
}

const char *sieve_get_capabilities(void)
{
	return sieve_listextensions(_interp);
}

bool sieve_init(const char *plugins ATTR_UNUSED)
{
    int res;

    _interp = NULL;

    res = sieve_interp_alloc(&_interp, NULL);
    if (res != SIEVE_OK)
	i_fatal("sieve_interp_alloc() returns %d\n", res);

    res = sieve_register_redirect(_interp, &sieve_redirect);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_redirect() returns %d\n", res);
    res = sieve_register_discard(_interp, &sieve_discard);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_discard() returns %d\n", res);
    res = sieve_register_reject(_interp, &sieve_reject);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_reject() returns %d\n", res);
    res = sieve_register_fileinto(_interp, &sieve_fileinto);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_fileinto() returns %d\n", res);
    res = sieve_register_keep(_interp, &sieve_keep);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_keep() returns %d\n", res);
    res = sieve_register_imapflags(_interp, &mark);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_imapflags() returns %d\n", res);
    res = sieve_register_notify(_interp, &sieve_notify);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_notify() returns %d\n", res);
    res = sieve_register_size(_interp, &getsize);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_size() returns %d\n", res);
    res = sieve_register_header(_interp, &getheader);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_header() returns %d\n", res);

    res = sieve_register_envelope(_interp, &getenvelope);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_envelope() returns %d\n", res);
    res = sieve_register_body(_interp, &getbody);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_body() returns %d\n", res);
    res = sieve_register_include(_interp, &getinclude);
    if (res != SIEVE_OK)
	i_fatal("sieve_registerinclude() returns %d\n", res);
    res = sieve_register_vacation(_interp, &vacation);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_vacation() returns %d\n", res);
    res = sieve_register_parse_error(_interp, &sieve_parse_error_handler);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_parse_error() returns %d\n", res);
    res = sieve_register_execute_error(_interp,  &sieve_execute_error_handler);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_execute_error() returns %d\n", res);

	return TRUE;
}

void sieve_deinit(void)
{
}

