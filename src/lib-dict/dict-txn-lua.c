/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dict.h"
#include "dlua-script-private.h"
#include "dict-lua-private.h"
#include "dlua-wrapper.h"

struct lua_dict_txn {
	pool_t pool;
	struct dict_transaction_context *txn;
	enum {
		STATE_OPEN,
		STATE_COMMITTED,
		STATE_ABORTED,
	} state;

	lua_State *L;
};

static int lua_dict_transaction_rollback(lua_State *L);
static int lua_dict_transaction_commit(lua_State *L);
static int lua_dict_set(lua_State *L);

static luaL_Reg lua_dict_txn_methods[] = {
	{ "rollback", lua_dict_transaction_rollback },
	{ "commit", lua_dict_transaction_commit },
	{ "set", lua_dict_set },
	{ NULL, NULL },
};

static void sanity_check_txn(lua_State *L, struct lua_dict_txn *txn)
{
	switch (txn->state) {
	case STATE_OPEN:
		return;
	case STATE_COMMITTED:
		luaL_error(L, "dict transaction already committed");
		return;
	case STATE_ABORTED:
		luaL_error(L, "dict transaction already aborted");
		return;
	}

	i_unreached();
}

/* no actual ref counting, but we use it for clean up */
static void lua_dict_txn_unref(struct lua_dict_txn *txn)
{
	/* rollback any transactions that were forgotten about */
	dict_transaction_rollback(&txn->txn);

	pool_unref(&txn->pool);
}

DLUA_WRAP_C_DATA(dict_txn, struct lua_dict_txn, lua_dict_txn_unref,
		 lua_dict_txn_methods);

/*
 * Abort a transaction [-1,+0,e]
 *
 * Args:
 *   1) userdata: struct lua_dict_txn *
 */
static int lua_dict_transaction_rollback(lua_State *L)
{
	struct lua_dict_txn *txn;

	DLUA_REQUIRE_ARGS(L, 1);

	txn = xlua_dict_txn_getptr(L, 1, NULL);
	sanity_check_txn(L, txn);

	txn->state = STATE_ABORTED;
	dict_transaction_rollback(&txn->txn);

	return 0;
}

static int lua_dict_transaction_commit_continue(lua_State *L,
						int status ATTR_UNUSED,
						lua_KContext ctx ATTR_UNUSED)
{
	if (!lua_isnil(L, -1))
		lua_error(L); /* commit failed */

	lua_pop(L, 1); /* pop the nil indicating the lack of error */

	return 0;
}

static void
lua_dict_transaction_commit_callback(const struct dict_commit_result *result,
				     struct lua_dict_txn *txn)
{

	switch (result->ret) {
	case DICT_COMMIT_RET_OK:
		/* push a nil to indicate everything is ok */
		lua_pushnil(txn->L);
		break;
	case DICT_COMMIT_RET_NOTFOUND:
		/* we don't expose dict_atomic_inc(), so this should never happen */
		i_unreached();
	case DICT_COMMIT_RET_FAILED:
	case DICT_COMMIT_RET_WRITE_UNCERTAIN:
		/* push the error we'll raise when we resume */
		i_assert(result->error != NULL);
		lua_pushfstring(txn->L, "dict transaction commit failed: %s",
				result->error);
		break;
	}

	dlua_pcall_yieldable_resume(txn->L, 1);
}

/*
 * Commit a transaction [-1,+0,e]
 *
 * Args:
 *   1) userdata: struct lua_dict_txn *
 */
static int lua_dict_transaction_commit(lua_State *L)
{
	struct lua_dict_txn *txn;

	DLUA_REQUIRE_ARGS(L, 1);

	txn = xlua_dict_txn_getptr(L, 1, NULL);
	sanity_check_txn(L, txn);

	txn->state = STATE_COMMITTED;
	dict_transaction_commit_async(&txn->txn,
		lua_dict_transaction_commit_callback, txn);

	return lua_dict_transaction_commit_continue(L,
		lua_yieldk(L, 0, 0, lua_dict_transaction_commit_continue), 0);
}

/*
 * Set key to value [-3,+0,e]
 *
 * Args:
 *   1) userdata: struct lua_dict_txn *
 *   2) string: key
 *   3) string: value
 */
static int lua_dict_set(lua_State *L)
{
	struct lua_dict_txn *txn;
	const char *key, *value;

	DLUA_REQUIRE_ARGS(L, 3);

	txn = xlua_dict_txn_getptr(L, 1, NULL);
	key = luaL_checkstring(L, 2);
	value = luaL_checkstring(L, 3);

	dict_set(txn->txn, key, value);

	return 0;
}

/*
 * Start a dict transaction [-1,+1,e]
 *
 * Args:
 *   1) userdata: struct dict *
 *
 * Returns:
 *   Returns a new transaction object.
 */
int lua_dict_transaction_begin(lua_State *L)
{
	struct lua_dict_txn *txn;
	struct dict *dict;
	pool_t pool;

	DLUA_REQUIRE_ARGS(L, 1);

	dict = dlua_check_dict(L, 1);

	pool = pool_alloconly_create("lua dict txn", 128);
	txn = p_new(pool, struct lua_dict_txn, 1);
	txn->pool = pool;
	txn->txn = dict_transaction_begin(dict);
	txn->state = STATE_OPEN;
	txn->L = L;

	xlua_pushdict_txn(L, txn, FALSE);

	return 1;
}
