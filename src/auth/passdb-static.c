/* Copyright (c) 2010-2015 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"
#include "passdb-template.h"

struct static_passdb_module {
	struct passdb_module module;
	struct passdb_template *tmpl;
	const char *static_password_tmpl;
};

static enum passdb_result
static_save_fields(struct auth_request *request, const char **password_r)
{
	struct static_passdb_module *module =
		(struct static_passdb_module *)request->passdb->passdb;

	auth_request_log_debug(request, AUTH_SUBSYS_DB, "lookup");
	passdb_template_export(module->tmpl, request);

	if (module->static_password_tmpl != NULL) {
		*password_r = t_auth_request_var_expand(
			module->static_password_tmpl, request, NULL);
	} else if (auth_fields_exists(request->extra_fields, "nopassword")) {
		*password_r = "";
	} else {
		auth_request_log_info(request, AUTH_SUBSYS_DB,
			"No password returned (and no nopassword)");
		*password_r = NULL;
		return PASSDB_RESULT_PASSWORD_MISMATCH;
	}
	return PASSDB_RESULT_OK;
}

static void
static_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	enum passdb_result result;
	const char *static_password;
	int ret;

	result = static_save_fields(request, &static_password);
	if (result != PASSDB_RESULT_OK) {
		callback(result, request);
		return;
	}

	ret = auth_request_password_verify(request, password, static_password,
					   STATIC_PASS_SCHEME, AUTH_SUBSYS_DB);
	if (ret <= 0) {
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	callback(PASSDB_RESULT_OK, request);
}

static void
static_lookup_credentials(struct auth_request *request,
			  lookup_credentials_callback_t *callback)
{
	enum passdb_result result;
	const char *static_password;

	result = static_save_fields(request, &static_password);
	passdb_handle_credentials(result, static_password,
				  STATIC_PASS_SCHEME, callback, request);
}

static struct passdb_module *
static_preinit(pool_t pool, const char *args)
{
	struct static_passdb_module *module;
	const char *value;

	module = p_new(pool, struct static_passdb_module, 1);
	module->tmpl = passdb_template_build(pool, args);

	if (passdb_template_remove(module->tmpl, "password", &value))
		module->static_password_tmpl = value;
	return &module->module;
}

struct passdb_module_interface passdb_static = {
	"static",

	static_preinit,
	NULL,
	NULL,

	static_verify_plain,
	static_lookup_credentials,
	NULL
};
