/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "home-expand.h"
#include "deliver.h"
#include "cmusieve-plugin.h"

#include <stdlib.h>
#include <sys/stat.h>

#define SIEVE_SCRIPT_PATH "~/.dovecot.sieve"

static deliver_mail_func_t *next_deliver_mail;
struct et_list *_et_list = NULL;

static const char *get_sieve_path(void)
{
	const char *script_path, *home;
	struct stat st;

	home = getenv("HOME");

	/* userdb may specify Sieve path */
	script_path = getenv("SIEVE");
	if (script_path != NULL) {
		if (*script_path == '\0') {
			/* disabled */
			return NULL;
		}
		script_path = home_expand(script_path);

		if (*script_path != '/' && *script_path != '\0') {
			/* relative path. change to absolute. */
			script_path = t_strconcat(getenv("HOME"), "/",
						  script_path, NULL);
		}
	} else {
		if (home == NULL) {
			i_error("Per-user script path is unknown. See "
				"http://wiki.dovecot.org/LDA/Sieve#location");
			return NULL;
		}

		script_path = home_expand(SIEVE_SCRIPT_PATH);
	}

	if (stat(script_path, &st) < 0) {
		if (errno != ENOENT)
			i_error("stat(%s) failed: %m", script_path);

		/* use global script instead, if one exists */
		script_path = getenv("SIEVE_GLOBAL_PATH");
		if (script_path == NULL) {
			/* for backwards compatibility */
			script_path = getenv("GLOBAL_SCRIPT_PATH");
		}
	}

	return script_path;
}

static int
cmusieve_deliver_mail(struct mail_storage *storage, struct mail *mail,
		      const char *username, const char *mailbox)
{
	const char *script_path;

	script_path = get_sieve_path();
	if (script_path == NULL)
		return 0;

	if (getenv("DEBUG") != NULL)
		i_info("cmusieve: Using sieve path: %s", script_path);

	return cmu_sieve_run(storage, mail, script_path, username, mailbox);
}

void cmusieve_plugin_init(void)
{
	next_deliver_mail = deliver_mail;
	deliver_mail = cmusieve_deliver_mail;
}

void cmusieve_plugin_deinit(void)
{
	deliver_mail = next_deliver_mail;
}
