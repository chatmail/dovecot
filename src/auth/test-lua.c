/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-auth.h"

#ifdef BUILTIN_LUA
#include "istream.h"
#include "auth-settings.h"
#include "auth-request.h"
#include "db-lua.h"

static struct auth_settings test_lua_auth_set = {
	.master_user_separator = "",
	.default_realm = "",
	.username_format = "",
};

static struct auth_request *test_db_lua_auth_request_new(void)
{
	const char *error;
	struct auth_request *req = auth_request_new_dummy(NULL);
	req->set = global_auth_settings;
	struct event *event = event_create(req->event);
	array_push_back(&req->authdb_event, &event);
	req->passdb = passdb_mock();
	test_assert(auth_request_set_username(req, "testuser", &error));
	return req;
}

static void test_db_lua_auth_verify(void)
{
	struct auth_request *req = test_db_lua_auth_request_new();

	static const char *luascript =
"function auth_password_verify(req, pass)\n"
"  req:log_debug(\"user \" .. req.user)\n"
"  if req:password_verify(\"{SHA256-CRYPT}$5$XtUywQCSjW0zAJgE$YjuPKQnsLuH4iE9kranZyy1lbil5IrRUfs7X6EyJyG1\", pass) then\n"
"      return dovecot.auth.PASSDB_RESULT_OK, {}\n"
"  end\n"
"end\n";
	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("auth db lua passdb_verify");

        test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
        if (script != NULL) {
		test_assert(auth_lua_script_init(script, &error) == 0);
		test_assert(auth_lua_call_password_verify(script, req, "password", &error) == 1);
		dlua_script_unref(&script);
	}
	if (error != NULL) {
		i_error("Test failed: %s", error);
	}
	i_free(req->passdb);

	auth_request_passdb_lookup_end(req, PASSDB_RESULT_OK);
	auth_request_unref(&req);

	test_end();
}

static void test_db_lua_auth_lookup_numberish_value(void)
{
	const char *scheme,*pass;

	struct auth_request *req = test_db_lua_auth_request_new();

	static const char *luascript =
"function auth_passdb_lookup(req)\n"
"  local fields = {}\n"
"  fields[\"user\"] = \"01234\"\n"
"  return dovecot.auth.PASSDB_RESULT_OK, fields\n"
"end\n";
	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("auth db lua passdb_lookup");

	test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
	if (script != NULL) {
		test_assert(auth_lua_script_init(script, &error) == 0);
		test_assert(auth_lua_call_passdb_lookup(script, req, &scheme, &pass, &error) == 1);
		test_assert(strcmp(req->fields.user, "01234") == 0);
		dlua_script_unref(&script);
	}
	if (error != NULL) {
		i_error("Test failed: %s", error);
	}
	i_free(req->passdb);
	auth_request_passdb_lookup_end(req, PASSDB_RESULT_OK);
	auth_request_unref(&req);

	test_end();
}

static void test_db_lua_auth_lookup(void)
{
	const char *scheme,*pass;

	struct auth_request *req = test_db_lua_auth_request_new();

	static const char *luascript =
"function auth_passdb_lookup(req)\n"
"  req:log_debug(\"user \" .. req.user)\n"
"  return dovecot.auth.PASSDB_RESULT_OK, req:var_expand(\"password=pass\")\n"
"end\n";
	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("auth db lua passdb_lookup");

	test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
	if (script != NULL) {
		test_assert(auth_lua_script_init(script, &error) == 0);
		test_assert(auth_lua_call_passdb_lookup(script, req, &scheme, &pass, &error) == 1);
		dlua_script_unref(&script);
	}
	if (error != NULL) {
		i_error("Test failed: %s", error);
	}
	i_free(req->passdb);
	auth_request_passdb_lookup_end(req, PASSDB_RESULT_OK);
	auth_request_unref(&req);

	test_end();
}

void test_db_lua(void) {
	memset(test_lua_auth_set.username_chars_map, 0xff,
	       sizeof(test_lua_auth_set.username_chars_map));
	global_auth_settings = &test_lua_auth_set;
	test_db_lua_auth_lookup();
	test_db_lua_auth_lookup_numberish_value();
	test_db_lua_auth_verify();
}

#endif
