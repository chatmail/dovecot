#ifndef DICT_LUA_H
#define DICT_LUA_H

#ifdef DLUA_WITH_YIELDS
/*
 * Internally, the dict methods yield via lua_yieldk() as implemented in Lua
 * 5.3 and newer.
 */

void dlua_push_dict(lua_State *L, struct dict *dict);
struct dict *dlua_check_dict(lua_State *L, int idx);

#endif

#endif
