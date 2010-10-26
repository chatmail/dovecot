/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "passdb.h"

#ifdef PASSDB_BSDAUTH

#include "safe-memset.h"
#include "auth-cache.h"
#include "mycrypt.h"

#include <login_cap.h>
#include <bsd_auth.h>
#include <pwd.h>

static void
bsdauth_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd *pw;
	int result;

	auth_request_log_debug(request, "bsdauth", "lookup");

	pw = getpwnam(request->user);
	if (pw == NULL) {
		auth_request_log_info(request, "bsdauth", "unknown user");
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	/* check if the password is valid */
	result = auth_userokay(request->user, NULL, NULL,
			       t_strdup_noconst(password));

	/* clear the passwords from memory */
	safe_memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

	if (result == 0) {
		auth_request_log_info(request, "bsdauth", "password mismatch");
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", pw->pw_name, NULL);

	callback(PASSDB_RESULT_OK, request);
}

static struct passdb_module *
bsdauth_preinit(struct auth_passdb *auth_passdb, const char *args)
{
	struct passdb_module *module;

	module = p_new(auth_passdb->auth->pool, struct passdb_module, 1);
	module->default_pass_scheme = "PLAIN"; /* same reason as PAM */

	if (strncmp(args, "cache_key=", 10) == 0) {
		module->cache_key =
			auth_cache_parse_key(auth_passdb->auth->pool,
					     args + 10);
	} else if (*args != '\0')
		i_fatal("passdb bsdauth: Unknown setting: %s", args);
	return module;
}

static void bsdauth_deinit(struct passdb_module *module ATTR_UNUSED)
{
	endpwent();
}

struct passdb_module_interface passdb_bsdauth = {
	"bsdauth",

	bsdauth_preinit,
	NULL,
	bsdauth_deinit,

	bsdauth_verify_plain,
	NULL,
	NULL
};
#else
struct passdb_module_interface passdb_bsdauth = {
	MEMBER(name) "bsdauth"
};
#endif