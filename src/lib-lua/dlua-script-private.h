#ifndef LUA_SCRIPT_PRIVATE_H
#define LUA_SCRIPT_PRIVATE_H 1

#include "dlua-script.h"
#include "lualib.h"
#include "lauxlib.h"

#if !defined(LUA_VERSION_NUM)
#define lua_setfield(L, i, k)   (lua_pushstring(L, k), lua_settable(L, i))
#define lua_getref(L, ref) lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
#define luaL_unref(L, ref) luaL_unref(L, LUA_REGISTRYINDEX, ref);
#endif

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
#define luaL_newmetatable(L, tn) \
	(luaL_newmetatable(L, tn) ? (lua_pushstring(L, tn), lua_setfield(L, -2, "__name"), 1) : 0)
#define luaL_newlibtable(L, l) (lua_createtable(L, 0, sizeof(l)/sizeof(*(l))-1))
#define luaL_newlib(L, l) (luaL_newlibtable(L, l), luaL_register(L, NULL, l))
#define lua_load(L, r, s, fn, m) lua_load(L, r, s, fn)
void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup);
void luaL_setmetatable (lua_State *L, const char *tname);
#endif

/* consistency helpers */
#define lua_isstring(L, n) (lua_isstring(L, n) == 1)
#define lua_isnumber(L, n) (lua_isnumber(L, n) == 1)
#define lua_toboolean(L, n) (lua_toboolean(L, n) == 1)

#define DLUA_TABLE_STRING(n, s) { .name = n, .type = DLUA_TABLE_VALUE_STRING, .v.s = s }
#define DLUA_TABLE_INTEGER(n, i) { .name = n, .type = DLUA_TABLE_VALUE_INTEGER, .v.i = i }
#define DLUA_TABLE_ENUM(n) { .name = #n, .type = DLUA_TABLE_VALUE_INTEGER, .v.i = n }
#define DLUA_TABLE_DOUBLE(n, d) { .name = n, .type = DLUA_TABLE_VALUE_DOUBLE, .v.d = d }
#define DLUA_TABLE_BOOLEAN(n, b) { .name = n, .type = DLUA_TABLE_VALUE_BOOLEAN, .v.b = b }
#define DLUA_TABLE_NULL(n, s) { .name = n, .type = DLUA_TABLE_VALUE_NULL }
#define DLUA_TABLE_END { .name = NULL }

struct dlua_script {
	struct dlua_script *prev,*next;
	pool_t pool;

	lua_State *L;

	const char *filename;
	struct istream *in;
	ssize_t last_read;

	int ref;
	bool init:1;
};

enum dlua_table_value_type {
	DLUA_TABLE_VALUE_STRING = 0,
	DLUA_TABLE_VALUE_INTEGER,
	DLUA_TABLE_VALUE_DOUBLE,
	DLUA_TABLE_VALUE_BOOLEAN,
	DLUA_TABLE_VALUE_NULL
};

struct dlua_table_values {
	const char *name;
	enum dlua_table_value_type type;
	union {
		const char *s;
		ptrdiff_t i;
		double d;
		bool b;
	} v;
};

/* Get dlua_script from lua_State */
struct dlua_script *dlua_script_from_state(lua_State *L);

/* register 'dovecot' global */
void dlua_dovecot_register(struct dlua_script *script);

/* push 'dovecot' global on top of stack */
void dlua_getdovecot(struct dlua_script *script);

/* assign values to table on idx */
void dlua_setmembers(struct dlua_script *script,
		     const struct dlua_table_values *values, int idx);


#endif
