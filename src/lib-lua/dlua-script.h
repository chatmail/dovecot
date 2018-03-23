#ifndef LUA_SCRIPT_H
#define LUA_SCRIPT_H 1

struct dlua_script;

/* Parse and load a lua script. Will reuse an existing script
   if found. */
int dlua_script_create_string(const char *str, struct dlua_script **script_r,
				  const char **error_r);
int dlua_script_create_file(const char *file, struct dlua_script **script_r,
				const char **error_r);
/* Remember to set script name using i_stream_set_name */
int dlua_script_create_stream(struct istream *is, struct dlua_script **script_r,
				  const char **error_r);

/* run dlua_script_init function */
int dlua_script_init(struct dlua_script *script, const char **error_r);

/* Reference lua script */
void dlua_script_ref(struct dlua_script *script);

/* Unreference a script, calls deinit and frees when no more
   references exist */
void dlua_script_unref(struct dlua_script **_script);

/* see if particular function is registered */
bool dlua_script_has_function(struct dlua_script *script, const char *fn);

#endif
