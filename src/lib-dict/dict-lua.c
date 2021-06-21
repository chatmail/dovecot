/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict.h"
#include "dlua-script-private.h"
#include "dict-lua-private.h"
#include "dlua-wrapper.h"

static int lua_dict_lookup(lua_State *);

static luaL_Reg lua_dict_methods[] = {
	{ "lookup", lua_dict_lookup },
	{ "iterate", lua_dict_iterate },
	{ "transaction_begin", lua_dict_transaction_begin },
	{ NULL, NULL },
};

/* no actual ref counting */
static void lua_dict_unref(struct dict *dict ATTR_UNUSED)
{
}

DLUA_WRAP_C_DATA(dict, struct dict, lua_dict_unref, lua_dict_methods);

static int lua_dict_async_continue(lua_State *L,
				   int status ATTR_UNUSED,
				   lua_KContext ctx ATTR_UNUSED)
{
	/*
	 * lua_dict_*_callback() already pushed the result table or error
	 * string.  We simply need to return/error out.
	 */

	if (lua_istable(L, -1))
		return 1;
	else
		return lua_error(L);
}

static void lua_dict_lookup_callback(const struct dict_lookup_result *result,
				     lua_State *L)
{
	if (result->ret < 0) {
		lua_pushstring(L, result->error);
	} else {
		unsigned int i;

		lua_newtable(L);

		for (i = 0; i < str_array_length(result->values); i++) {
			lua_pushstring(L, result->values[i]);
			lua_seti(L, -2, i + 1);
		}
	}

	dlua_pcall_yieldable_resume(L, 1);
}

/*
 * Lookup a key in dict [-2,+1,e]
 *
 * Args:
 *   1) userdata: struct dict *dict
 *   2) string: key
 *
 * Returns:
 *   If key is found, returns a table with values.  If key is not found,
 *   returns nil.
 */
static int lua_dict_lookup(lua_State *L)
{
	struct dict *dict;
	const char *key;

	DLUA_REQUIRE_ARGS(L, 2);

	dict = xlua_dict_getptr(L, 1, NULL);
	key = luaL_checkstring(L, 2);

	dict_lookup_async(dict, key, lua_dict_lookup_callback, L);

	return lua_dict_async_continue(L,
		lua_yieldk(L, 0, 0, lua_dict_async_continue), 0);
}

void dlua_push_dict(lua_State *L, struct dict *dict)
{
	xlua_pushdict(L, dict, FALSE);
}

struct dict *dlua_check_dict(lua_State *L, int idx)
{
	return xlua_dict_getptr(L, idx, NULL);
}
